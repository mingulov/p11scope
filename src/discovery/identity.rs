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
use std::sync::atomic::{AtomicU64, Ordering};

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
use crate::semantics_edge::resources::{
    OWNED_ALLOCATION_PADDING, ResourceLease, SemanticResourceRefusal, SemanticResourceReserver,
};

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
    Ok(pin_from_metadata(&md))
}

fn pin_from_metadata(md: &std::fs::Metadata) -> Pin {
    Pin {
        ino: md.ino(),
        size: md.len(),
        ctime: (md.ctime(), md.ctime_nsec()),
    }
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
    /// Calibrated through this opened file, while its pin was unchanged.
    /// Keeping the proof avoids mapping a watched file in the observer again.
    mapped: Option<MappedFile>,
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

/// A collection's finite snapshot of already-retained attach targets. Every
/// proof owns the original file Arc; it neither reopens nor duplicates an fd.
/// The key is fstat-to-fstat only, never a maps device or pathname.
#[derive(Debug, Default)]
pub(crate) struct RetainedMappedIdentities {
    files: BTreeMap<FileIdentity, RetainedMappedIdentity>,
}

#[derive(Debug)]
struct RetainedMappedIdentity {
    file: Arc<std::fs::File>,
    pin: Pin,
    mapped: MappedFile,
}

impl RetainedMappedIdentities {
    pub(crate) fn from_targets<'a>(
        targets: impl IntoIterator<Item = &'a RetainedInventoryTarget>,
    ) -> Self {
        let mut result = Self::default();
        for target in targets {
            let entry = &target.entry;
            if target.changed.get() {
                continue;
            }
            let Some(mapped) = entry.reusable_mapped_file() else {
                continue;
            };
            let Ok(metadata) = entry.file.metadata() else {
                continue;
            };
            result
                .files
                .entry(FileIdentity::of(&metadata))
                .or_insert_with(|| RetainedMappedIdentity {
                    file: Arc::clone(&entry.file),
                    pin: entry.pin,
                    mapped,
                });
        }
        result
    }

    pub(crate) fn identity_for(&self, file: &std::fs::File) -> Option<MappedFile> {
        let metadata = file.metadata().ok()?;
        let held = self.files.get(&FileIdentity::of(&metadata))?;
        // The held fd prevents inode/device reuse; both it and the freshly
        // opened file must still match the calibrated metadata. Changed or
        // unmatched files go through the normal probe and hash checks.
        (pin_from_metadata(&metadata) == held.pin
            && pin_of(&held.file).is_ok_and(|current| current == held.pin))
        .then_some(held.mapped)
    }
}

impl RetainedInventoryTarget {
    /// Extra owned allocations made by `share`, without performing the copy
    /// or exposing identity words. Entry's raw path and display path are two
    /// independently cloned strings. File/export Arc clones share their
    /// existing backing; their inline holders are charged by the caller.
    pub(crate) fn retained_copy_allocation_charge(&self) -> Option<usize> {
        retained_entry_copy_allocation_charge(&self.entry)
    }

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

    /// Borrow the original opened file and canonical digest without copying
    /// identity or opening another descriptor. Callers retain ABI/pin checks.
    pub(crate) fn borrowed_file_and_digest(&self) -> (&std::fs::File, &str) {
        (&self.entry.file, &self.entry.sha256)
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

fn retained_entry_copy_allocation_charge(entry: &Entry) -> Option<usize> {
    [
        Some(&entry.raw.path),
        Some(&entry.path),
        Some(&entry.sha256),
        entry.build_id.as_ref(),
    ]
    .into_iter()
    .flatten()
    .filter(|text| text.capacity() != 0)
    .try_fold(0usize, |bytes, text| {
        bytes
            .checked_add(text.capacity())?
            .checked_add(crate::semantics_edge::resources::OWNED_ALLOCATION_PADDING)
    })
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
    // `f_type` is signed on glibc and unsigned on musl; the magic fits both.
    #[allow(clippy::unnecessary_cast)]
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
    #[allow(clippy::unnecessary_cast)]
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
///   `mmap` installs the BACKING file in the VMA (in v6.6 `ovl_mmap`
///   calls `vma_set_file(vma, realfile)` directly; the
///   `backing_file_mmap` step appears only in v6.8 `fs/backing-file.c`);
///   what changed around 6.8 is only what procfs renders for maps
///   lines. Before, maps shows the backing file itself (observed on
///   6.1 and 6.6, 5498046); from then on it renders the user-visible
///   overlay file (`file_user_inode` in `show_map_vma`; read in the
///   6.17 source). `map_files` stat is the overlay identity on BOTH
///   sides of 6.8, never the backing file: probed on 6.6.157 and
///   7.0.14 (upper-only, lower-layer and second-mount files,
///   xino=off), the `map_files` stat always equals `fstat` of the
///   same path — when the layers are on different filesystems, with
///   xino=off both even share the layer's pseudo `st_dev` (upper
///   `(49, *)`, lower `(50, *)` while the mount itself is `0:48` on
///   6.6), never the backing device maps shows pre-6.8.
/// - So both sides compare like-for-like by construction: the candidate
///   side stats the target's `map_files` range; the pinned side mmaps
///   the held fd itself (one private read-only page, like
///   `KernelSelfMappingProbe`) and stats `/proc/self/map_files` for
///   that mapping. That the `map_files` stat equals `fstat` of the
///   same path is observed (probed on both sides of 6.8) but not
///   relied on. The same kernel path installs both VMAs and the same
///   procfs code renders both
///   (overlay or not, before or after 6.8), so equal identities are the
///   same kernel file: on btrfs the subvolume's `(anon dev, ino)`, unique;
///   on overlay both render this mount's view of the file, which is also
///   why a second mount of the same lower file compares unequal (probed
///   `(66, 11)` vs `(68, 11)` on 6.6).
/// - Following a `map_files` link needs `CAP_SYS_ADMIN` or
///   `CAP_CHECKPOINT_RESTORE` in the initial user namespace (`EPERM`
///   otherwise), for `/proc/self` too. Without it nothing is proven and
///   C1b fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct FileIdentity {
    pub dev: u64,
    pub ino: u64,
}

impl FileIdentity {
    fn of(metadata: &std::fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }
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
    /// These filesystems preserve the mapping behind a held, unchanged file.
    /// Btrfs is included here because fstat-to-fstat includes the subvolume
    /// device; it still requires every target range's map_files proof below.
    /// Overlay backing switches, wrapping tmpfs inode numbers and unknown
    /// filesystems keep the ordinary fresh self-mapping probe.
    fn may_retain(&self) -> bool {
        self.fs_magic.is_some_and(|magic| {
            magic == 0x9123_683e
                || KEY_IS_IDENTITY_FILESYSTEMS
                    .iter()
                    .any(|(allowed, _)| *allowed == magic)
        })
    }

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
            #[allow(clippy::unnecessary_cast)]
            let magic = (unsafe { buf.assume_init().f_type }) as u64 & 0xffff_ffff;
            magic
        })
    });
    Ok(MappedFile { identity, fs_magic })
}

#[cfg(test)]
pub(crate) fn self_mapped_identity(file: &std::fs::File) -> Result<FileIdentity, String> {
    self_mapped_file(file).map(|mapped| mapped.identity)
}

/// The `vm_file` identity of a held fd: mmap one page (`PROT_READ`,
/// `MAP_PRIVATE`, never `PROT_EXEC`, unmapped on every path) and stat this
/// process's own `map_files` entry for it. Like-for-like with
/// [`map_files_identity`] of a target that maps the same file. Includes the
/// filesystem magic of that same entry, read while the self-mapping exists.
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
    fn reusable_mapped_file(&self) -> Option<MappedFile> {
        self.mapped.filter(|mapped| {
            !self.overlay
                && !self.collapsed
                && mapped.may_retain()
                && pin_of(&self.file).is_ok_and(|current| current == self.pin)
        })
    }

    fn new(
        file: std::fs::File,
        pin: Pin,
        path: String,
        inspected: &InspectedObject,
        raw: RawObjectInstance,
        mapping: MappingFileKey,
        mapped: Option<MappedFile>,
    ) -> Result<Self, String> {
        Ok(Self {
            overlay: on_overlayfs(file.as_raw_fd())?,
            collapsed: false,
            raw,
            mapping,
            file: Arc::new(file),
            pin,
            mapped,
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
#[derive(Debug)]
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
    // Process-local cache fences only, never object/admission/attachment IDs.
    copy_source: Option<PinCopyCacheId>,
    copy_version: u64,
}

impl Clone for PinnedObjects {
    fn clone(&self) -> Self {
        Self {
            by_id: self.by_id.clone(),
            raw_to_id: self.raw_to_id.clone(),
            rejected_keys: self.rejected_keys.clone(),
            ambiguous_keys: self.ambiguous_keys.clone(),
            ambiguity_published: self.ambiguity_published.clone(),
            ownership: self.ownership.clone(),
            raw_ownership: self.raw_ownership.clone(),
            next_id: self.next_id,
            overlay_uncertain: self.overlay_uncertain,
            changed: std::cell::Cell::new(self.changed.get()),
            revision: self.revision,
            copy_source: mint_pin_copy_cache_id(&NEXT_PIN_COPY_SOURCE),
            copy_version: self.copy_version,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PinCopyCacheId(std::num::NonZeroU64);

impl std::fmt::Debug for PinCopyCacheId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PinCopyCacheId(<private>)")
    }
}

static NEXT_PIN_COPY_SOURCE: AtomicU64 = AtomicU64::new(0);
static NEXT_PIN_COPY_SELECTION: AtomicU64 = AtomicU64::new(0);

fn mint_pin_copy_cache_id(counter: &AtomicU64) -> Option<PinCopyCacheId> {
    let previous = counter
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |old| {
            old.checked_add(1)
        })
        .ok()?;
    std::num::NonZeroU64::new(previous + 1).map(PinCopyCacheId)
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
            copy_source: mint_pin_copy_cache_id(&NEXT_PIN_COPY_SOURCE),
            copy_version: 0,
        }
    }

    /// The current membership revision for the pin-sweep gate.
    pub fn revision(&self) -> u64 {
        self.revision
    }

    fn bump_revision(&mut self) {
        self.revision = self.revision.saturating_add(1);
        self.bump_copy_version();
    }

    fn bump_copy_version(&mut self) {
        self.copy_version = self.copy_version.saturating_add(1);
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

    /// Read-only bound before the first retained-target clone. The same
    /// field/capacity arithmetic also charges later `share` copies; identity
    /// checks and retention remain the responsibility of their existing path.
    pub(crate) fn retained_target_copy_allocation_charge(
        &self,
        id: PinnedObjectId,
    ) -> Option<usize> {
        retained_entry_copy_allocation_charge(self.by_id.get(&id)?)
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
        self.bump_copy_version();
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
        self.bump_copy_version();
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

    /// The held object's `vm_file` identity ([`self_mapped_file`]):
    /// what another process's `map_files` range must equal before a maps
    /// key may stand for this object there (C1b sweep matching).
    pub(crate) fn object_mapped_identity(&self, id: PinnedObjectId) -> Result<MappedFile, String> {
        let entry = self
            .by_id
            .get(&id)
            .ok_or_else(|| format!("object {id:?} was not pinned"))?;
        match entry.reusable_mapped_file() {
            Some(mapped) => Ok(mapped),
            None => self_mapped_file(&entry.file),
        }
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
        self.bump_copy_version();
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
        self.bump_copy_version();
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
        self.bump_copy_version();
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

// Inactive collected graph-builder boundary. Ready is structural and borrowed;
// Engine installation must first supply its own persistent backing-lease sink.
#[allow(unused_imports)]
pub(crate) use conservative_copy::{
    ConservativePinSelection, GraphRefusal, GraphStep, InstalledModulesBacking,
    InstalledPinsBacking, PinnedConservativeCursor, RetainedScannedInputs, RetiredFileHandoff,
    ScannedInputMeasure, ScannedRebindCursor,
};
#[cfg(test)]
use conservative_copy::{conservative_pin_tree_bytes, deallocate_drained_unique_arc};

#[allow(dead_code)] // Staged pure builders, not yet selected by the live Engine.
mod conservative_copy {
    use super::*;
    use std::ops::Bound::{Excluded, Unbounded};

    const TEXT_QUANTUM: usize = 4096;

    /// Value construction only: none of these outcomes establish native or
    /// semantic readiness, retirement, admission, or receipt authority.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum GraphStep {
        Yielded,
        Advanced,
        Ready,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum GraphRefusal {
        Storage(SemanticResourceRefusal),
        SourceChanged,
        Identity,
        Overflow,
        Cancelled,
    }

    /// Immutable original selection and its actual same-pool payment. Neither
    /// equal cardinalities nor a reused Vec/tree allocation can resume a cursor.
    #[derive(Debug)]
    pub(crate) struct ConservativePinSelection {
        retired: BTreeSet<ProcessViewId>,
        rejected: BTreeSet<ObjectKey>,
        identity: PinCopyCacheId,
        storage: ResourceLease,
    }

    #[derive(Debug)]
    pub(crate) struct ConservativePinSelectionRefusal {
        retired: BTreeSet<ProcessViewId>,
        rejected: BTreeSet<ObjectKey>,
        storage: ResourceLease,
    }

    impl ConservativePinSelectionRefusal {
        /// O(1) owner return; disposal of these original trees remains explicit.
        pub(crate) fn into_originals(
            self,
        ) -> (BTreeSet<ProcessViewId>, BTreeSet<ObjectKey>, ResourceLease) {
            (self.retired, self.rejected, self.storage)
        }
    }

    impl ConservativePinSelection {
        pub(crate) fn storage_bound(retired: usize, rejected: usize) -> Option<usize> {
            std::mem::size_of::<Self>()
                .checked_add(conservative_pin_tree_bytes::<ProcessViewId, ()>(retired)?)?
                .checked_add(conservative_pin_tree_bytes::<ObjectKey, ()>(rejected)?)
        }

        pub(crate) fn from_reserved_originals(
            retired: BTreeSet<ProcessViewId>,
            rejected: BTreeSet<ObjectKey>,
            storage: ResourceLease,
            reserve: &SemanticResourceReserver,
        ) -> Result<Self, ConservativePinSelectionRefusal> {
            let required = Self::storage_bound(retired.len(), rejected.len());
            let identity = required
                .filter(|bytes| reserve.covers(&storage, *bytes))
                .and_then(|_| mint_pin_copy_cache_id(&NEXT_PIN_COPY_SELECTION));
            match identity {
                Some(identity) => Ok(Self {
                    retired,
                    rejected,
                    identity,
                    storage,
                }),
                None => Err(ConservativePinSelectionRefusal {
                    retired,
                    rejected,
                    storage,
                }),
            }
        }

        fn retires(&self, source: &PinnedObjects, view: ProcessViewId) -> bool {
            self.retired.contains(&view) && source.ownership.contains_key(&view)
        }

        pub(crate) fn retired(&self) -> &BTreeSet<ProcessViewId> {
            &self.retired
        }

        pub(crate) fn rejected(&self) -> &BTreeSet<ObjectKey> {
            &self.rejected
        }
    }

    /// Rust 1.99.1 alloc::collections::btree::node has B=6: eleven key/value
    /// slots, twelve edges, and a 16-byte header on Linux x86-64. Every
    /// non-root node keeps at least five keys after insert, remove, append
    /// and clone (MIN_LEN), so n entries need at most 1+(n-1)/5 nodes; an
    /// empty map allocates nothing. The node size is the full internal size,
    /// applied to every node, so this dominates retained nodes. These actual
    /// private key/value types have alignment <=8; other layouts refuse.
    pub(super) fn conservative_pin_tree_bytes<K, V>(entries: usize) -> Option<usize> {
        fn align8(bytes: usize) -> Option<usize> {
            bytes.checked_add(7).map(|value| value & !7)
        }
        if std::mem::align_of::<K>() > 8 || std::mem::align_of::<V>() > 8 {
            return None;
        }
        let node = 16usize
            .checked_add(align8(std::mem::size_of::<K>().checked_mul(11)?)?)?
            .checked_add(align8(std::mem::size_of::<V>().checked_mul(11)?)?)?
            .checked_add(12 * 8)?
            .checked_add(OWNED_ALLOCATION_PADDING)?;
        let nodes = if entries == 0 {
            0
        } else {
            1 + (entries - 1) / 5
        };
        nodes.checked_mul(node)
    }

    fn bytes_for<T>(count: usize) -> Result<usize, GraphRefusal> {
        count
            .checked_mul(std::mem::size_of::<T>())
            .and_then(|bytes| bytes.checked_add(OWNED_ALLOCATION_PADDING))
            .ok_or(GraphRefusal::Overflow)
    }

    fn tree<K, V>(count: usize) -> Result<usize, GraphRefusal> {
        conservative_pin_tree_bytes::<K, V>(count).ok_or(GraphRefusal::Overflow)
    }

    fn add(total: &mut usize, bytes: usize) -> Result<(), GraphRefusal> {
        *total = total.checked_add(bytes).ok_or(GraphRefusal::Overflow)?;
        Ok(())
    }

    fn text_bytes(text: &str) -> Result<usize, GraphRefusal> {
        text.len()
            .checked_add(OWNED_ALLOCATION_PADDING)
            .ok_or(GraphRefusal::Overflow)
    }

    fn copy_text(target: &mut String, original: &str) -> bool {
        let start = target.len();
        let mut end = start.saturating_add(TEXT_QUANTUM).min(original.len());
        while !original.is_char_boundary(end) {
            end -= 1;
        }
        target.push_str(&original[start..end]);
        end == original.len()
    }

    fn next_map<'a, K: Ord, V>(
        map: &'a BTreeMap<K, V>,
        after: Option<&K>,
    ) -> Option<(&'a K, &'a V)> {
        match after {
            Some(key) => map.range((Excluded(key), Unbounded)).next(),
            None => map.first_key_value(),
        }
    }

    fn next_set<'a, K: Ord>(set: &'a BTreeSet<K>, after: Option<&K>) -> Option<&'a K> {
        match after {
            Some(key) => set.range((Excluded(key), Unbounded)).next(),
            None => set.first(),
        }
    }

    // At most two owned resume keys. During measurement each actual allocation
    // is paid before its String is allocated. During construction the admitted
    // whole-envelope lease covers these buffers. Field order refunds only after
    // the owned String has been freed.
    struct RawResume {
        raw: RawObjectInstance,
        storage: Option<ResourceLease>,
    }

    #[derive(Default)]
    struct RawWalker {
        ended: bool,
        last: Option<RawResume>,
        incoming: Option<RawResume>,
    }

    impl RawWalker {
        fn after(&self) -> Option<&RawObjectInstance> {
            self.last.as_ref().map(|key| &key.raw)
        }

        /// One allocation or <=4096 bytes copied. `next` is borrowed directly
        /// from the fenced source at the successor of our paid original key.
        fn advance(
            &mut self,
            next: Option<&RawObjectInstance>,
            reserve: &SemanticResourceReserver,
            separately_paid: bool,
        ) -> Result<WalkStep, GraphRefusal> {
            if self.ended {
                return Ok(WalkStep::End);
            }
            let Some(next) = next else {
                self.ended = true;
                return Ok(WalkStep::End);
            };
            if self.incoming.is_none() {
                let storage = if separately_paid {
                    Some(
                        reserve
                            .reserve(text_bytes(&next.path)?)
                            .map_err(GraphRefusal::Storage)?,
                    )
                } else {
                    None
                };
                self.incoming = Some(RawResume {
                    raw: RawObjectInstance {
                        mount_namespace: next.mount_namespace,
                        key: next.key,
                        path: String::with_capacity(next.path.len()),
                    },
                    storage,
                });
                return Ok(WalkStep::Progress);
            }
            let incoming = self.incoming.as_mut().ok_or(GraphRefusal::Identity)?;
            if copy_text(&mut incoming.raw.path, &next.path) {
                // One old String leaf and its measurement lease die here.
                self.last = self.incoming.take();
                return Ok(WalkStep::Item);
            }
            Ok(WalkStep::Progress)
        }

        fn release_one(&mut self) -> bool {
            if self.incoming.take().is_some() {
                return false;
            }
            if self.last.take().is_some() {
                return false;
            }
            true
        }
    }

    #[derive(PartialEq, Eq)]
    enum WalkStep {
        Progress,
        Item,
        End,
    }

    struct EntryCopy {
        id: PinnedObjectId,
        entry: Entry,
        field: u8,
    }

    impl EntryCopy {
        fn new(id: PinnedObjectId, old: &Entry) -> Self {
            Self {
                id,
                entry: Entry {
                    raw: RawObjectInstance {
                        mount_namespace: old.raw.mount_namespace,
                        key: old.raw.key,
                        path: String::with_capacity(old.raw.path.len()),
                    },
                    mapping: old.mapping,
                    file: old.file.clone(),
                    pin: old.pin,
                    mapped: old.mapped,
                    path: String::new(),
                    sha256: String::new(),
                    build_id: old.build_id.as_ref().map(|_| String::new()),
                    abi: old.abi,
                    exports: old.exports.clone(),
                    overlay: old.overlay,
                    collapsed: old.collapsed,
                },
                field: 0,
            }
        }

        fn advance(&mut self, old: &Entry) -> bool {
            let (target, original) = match self.field {
                0 => (&mut self.entry.raw.path, old.raw.path.as_str()),
                1 => (&mut self.entry.path, old.path.as_str()),
                2 => (&mut self.entry.sha256, old.sha256.as_str()),
                3 => match (&mut self.entry.build_id, &old.build_id) {
                    (Some(target), Some(original)) => (target, original.as_str()),
                    _ => {
                        self.field = 4;
                        return false;
                    }
                },
                _ => return true,
            };
            if target.capacity() < original.len() {
                // Exactly one known request; no repeated growth or hidden peak.
                target.reserve_exact(original.len());
                return false;
            }
            if copy_text(target, original) {
                self.field += 1;
            }
            false
        }
    }

    struct EntryReclaim {
        id: PinnedObjectId,
        raw: String,
        path: String,
        digest: String,
        build: Option<String>,
        file: Option<Arc<std::fs::File>>,
        exports: Option<Arc<[(String, u64)]>>,
        field: u8,
        drained: usize,
    }

    impl EntryReclaim {
        fn new(id: PinnedObjectId, entry: Entry) -> Self {
            Self {
                id,
                raw: entry.raw.path,
                path: entry.path,
                digest: entry.sha256,
                build: entry.build_id,
                file: Some(entry.file),
                exports: Some(entry.exports),
                field: 0,
                drained: 0,
            }
        }

        fn advance(&mut self, source: Option<&PinnedObjects>) -> Result<bool, GraphRefusal> {
            match self.field {
                0 => drop(std::mem::take(&mut self.raw)),
                1 => drop(std::mem::take(&mut self.path)),
                2 => drop(std::mem::take(&mut self.digest)),
                3 => drop(self.build.take()),
                4 => {
                    let file = self.file.as_ref().ok_or(GraphRefusal::Identity)?;
                    if !source
                        .and_then(|pins| pins.by_id.get(&self.id))
                        .is_some_and(|held| Arc::ptr_eq(&held.file, file))
                    {
                        // Pure reclamation cannot close the last descriptor.
                        // An inode, independently opened FD, or reference count
                        // does not prove a LIVE owner of this exact File share.
                        return Err(GraphRefusal::Identity);
                    }
                    drop(self.file.take());
                }
                5 => {
                    let Some(exports) = self.exports.as_mut() else {
                        return Ok(true);
                    };
                    if source
                        .and_then(|pins| pins.by_id.get(&self.id))
                        .is_some_and(|held| Arc::ptr_eq(&held.exports, exports))
                    {
                        // A borrowed LIVE actual alias proves this release
                        // cannot run the final payload/slice destructor.
                        drop(self.exports.take());
                    } else {
                        let slice = Arc::get_mut(exports).ok_or(GraphRefusal::Identity)?;
                        if self.drained < slice.len() {
                            drop(std::mem::take(&mut slice[self.drained].0));
                            self.drained += 1;
                            return Ok(false);
                        }
                        // No callback, exposed Arc/element, or alias-creating
                        // operation between this exclusive recheck and transfer.
                        let slice = Arc::get_mut(exports).ok_or(GraphRefusal::Identity)?;
                        if self.drained != slice.len() {
                            return Err(GraphRefusal::Identity);
                        }
                        let exports = self.exports.take().ok_or(GraphRefusal::Identity)?;
                        // SAFETY: each String payload was mem::take+freed once;
                        // the remaining Strings have zero capacity and are valid.
                        // drained==len and get_mut just proved no other strong
                        // or Weak reference. Same allocation and slice metadata
                        // are consumed once, with no intervening observer.
                        unsafe {
                            deallocate_drained_unique_arc(exports);
                        }
                    }
                }
                _ => return Ok(true),
            }
            self.field += 1;
            Ok(false)
        }

        /// Installed-mode step: every field behaves as `advance` except the
        /// file share, which moves into the handoff when no live alias holds
        /// this exact share, and the exports share, which drops our clone
        /// when a Session-held clone proves our drop cannot be last. A full
        /// handoff refuses with the pool's own storage refusal; the file share
        /// is never dropped here.
        fn advance_installed(
            &mut self,
            source: Option<&PinnedObjects>,
            handoff: &mut RetiredFileHandoff,
            reserve: &SemanticResourceReserver,
        ) -> Result<bool, GraphRefusal> {
            if self.field != 4 && self.field != 5 {
                return self.advance(source);
            }
            if self.field == 5 {
                if let Some(exports) = self.exports.as_ref() {
                    let live_alias = source
                        .and_then(|pins| pins.by_id.get(&self.id))
                        .is_some_and(|held| Arc::ptr_eq(&held.exports, exports));
                    if !live_alias && Arc::strong_count(exports) > 1 {
                        // A Session-held clone (Singles retains the entry
                        // through its terminal detach) proves our drop cannot
                        // be the last one. Release our share as one leaf
                        // instead of forgetting the graph. Even a race could
                        // only free one slice bounded by standard names.
                        drop(self.exports.take());
                        self.field += 1;
                        return Ok(false);
                    }
                }
                return self.advance(source);
            }
            let file = self.file.as_ref().ok_or(GraphRefusal::Identity)?;
            if source
                .and_then(|pins| pins.by_id.get(&self.id))
                .is_some_and(|held| Arc::ptr_eq(&held.file, file))
            {
                drop(self.file.take());
            } else {
                let file = self.file.as_ref().ok_or(GraphRefusal::Identity)?;
                handoff.push(file).map_err(|()| {
                    reserve
                        .reserve(usize::MAX)
                        .err()
                        .map(GraphRefusal::Storage)
                        .unwrap_or(GraphRefusal::Identity)
                })?;
                drop(self.file.take());
            }
            self.field += 1;
            Ok(false)
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Phase {
        New,
        MeasureEntries,
        MeasureExports,
        MeasureClaims,
        MeasureRaws,
        MeasureOwnedRows,
        MeasureOwnedRaws,
        Admit,
        IndexClaims,
        IndexManifest,
        IndexRaws,
        Classify,
        Entries,
        RawMap,
        Ownership,
        RawOwnership,
        Rejected,
        Ambiguous,
        Published,
        ApplyRejected,
        Publish,
        Ready,
        Rebinding,
        RebindAborted,
        Installed,
        Reclaim,
        Reclaimed,
    }

    #[derive(Clone, Copy)]
    struct SourceFence {
        identity: PinCopyCacheId,
        revision: u64,
        copy_version: u64,
        changed: bool,
        selection: PinCopyCacheId,
    }

    impl SourceFence {
        fn new(
            source: &PinnedObjects,
            selection: &ConservativePinSelection,
        ) -> Result<Self, GraphRefusal> {
            if source.revision == u64::MAX || source.copy_version == u64::MAX {
                return Err(GraphRefusal::SourceChanged);
            }
            Ok(Self {
                identity: source.copy_source.ok_or(GraphRefusal::Identity)?,
                revision: source.revision,
                copy_version: source.copy_version,
                changed: source.changed.get(),
                selection: selection.identity,
            })
        }

        fn check(
            &self,
            source: &PinnedObjects,
            selection: &ConservativePinSelection,
        ) -> Result<(), GraphRefusal> {
            if source.copy_source != Some(self.identity) || selection.identity != self.selection {
                return Err(GraphRefusal::Identity);
            }
            if source.revision != self.revision
                || source.copy_version != self.copy_version
                || source.changed.get() != self.changed
                || source.revision == u64::MAX
                || source.copy_version == u64::MAX
            {
                return Err(GraphRefusal::SourceChanged);
            }
            Ok(())
        }
    }

    /// Payment for installed canonical pins: the install sink swaps the
    /// cursor's output into the canonical and moves these leases here. They
    /// stay charged while the canonical holds the installed output; dropping
    /// them refunds only after the old canonical was reclaimed.
    #[derive(Debug)]
    pub(crate) struct InstalledPinsBacking {
        claim_backing: Option<ResourceLease>,
        backing: Option<ResourceLease>,
        header: Option<ResourceLease>,
    }

    /// Every output/scratch allocation stays with these leases through borrowed
    /// Ready and bounded reclamation. There is deliberately no take/swap API.
    pub(crate) struct PinnedConservativeCursor {
        phase: Phase,
        fence: Option<SourceFence>,
        required: Option<usize>,
        measured: usize,
        output: Option<PinnedObjects>,
        skipped: Vec<Skipped>,
        removed_ids: BTreeSet<PinnedObjectId>,
        retained_ids: BTreeSet<PinnedObjectId>,
        rejected_ids: BTreeSet<PinnedObjectId>,
        removed_raws: BTreeSet<RawObjectInstance>,
        retained_raws: BTreeSet<RawObjectInstance>,
        walker: RawWalker,
        raw_copy: Option<RawObjectInstance>,
        raw_action: bool,
        entry: Option<EntryCopy>,
        reclaim_entry: Option<EntryReclaim>,
        claims: Option<(ProcessViewId, ViewClaims)>,
        skipped_leaf: Option<Skipped>,
        last_id: Option<PinnedObjectId>,
        last_view: Option<ProcessViewId>,
        active_view: Option<ProcessViewId>,
        last_key: Option<ObjectKey>,
        bucket: u8,
        index: usize,
        retired_count: u64,
        reclaim_phase: u8,
        after_claim_reclaim: u8,
        rebind_owner: Option<PinCopyCacheId>,
        installed: Option<PinCopyCacheId>,
        // A growing pin prefix stays with the SAME old H1 backing payment.
        rebind_old_pins: Option<(ProcessViewId, std::vec::IntoIter<PinnedObjectId>)>,
        rebind_complete: bool,
        // Owners above are released BEFORE the actual extra payment below.
        claim_backing: Option<ResourceLease>,
        backing: Option<ResourceLease>,
        header: Option<ResourceLease>,
    }

    impl PinnedConservativeCursor {
        pub(crate) fn new() -> Self {
            Self {
                phase: Phase::New,
                fence: None,
                required: None,
                measured: 0,
                output: None,
                skipped: Vec::new(),
                removed_ids: BTreeSet::new(),
                retained_ids: BTreeSet::new(),
                rejected_ids: BTreeSet::new(),
                removed_raws: BTreeSet::new(),
                retained_raws: BTreeSet::new(),
                walker: RawWalker::default(),
                raw_copy: None,
                raw_action: false,
                entry: None,
                reclaim_entry: None,
                claims: None,
                skipped_leaf: None,
                last_id: None,
                last_view: None,
                active_view: None,
                last_key: None,
                bucket: 0,
                index: 0,
                retired_count: 0,
                reclaim_phase: 0,
                after_claim_reclaim: 3,
                rebind_owner: None,
                installed: None,
                rebind_old_pins: None,
                rebind_complete: false,
                claim_backing: None,
                backing: None,
                header: None,
            }
        }

        pub(crate) fn pinned(&self) -> Option<&PinnedObjects> {
            // A completed bind keeps the Ready-style borrow while the loan is
            // outstanding; partial mid-bind claims stay hidden as before.
            (self.phase == Phase::Ready
                || (self.phase == Phase::Rebinding
                    && self.rebind_complete
                    && self.rebind_owner.is_some()))
            .then_some(self.output.as_ref())
            .flatten()
        }

        pub(crate) fn skipped(&self) -> Option<&[Skipped]> {
            (self.phase == Phase::Ready).then_some(self.skipped.as_slice())
        }

        /// The copy output while the rebind loan is outstanding. `Some` only
        /// in `Phase::Rebinding`: the graph's Plan/Facts read the loaned
        /// output through this, never through `pinned()`.
        pub(crate) fn loaned_output(&self) -> Option<&PinnedObjects> {
            (self.phase == Phase::Rebinding)
                .then_some(self.output.as_ref())
                .flatten()
        }

        /// Upper bound on retired files the installed reclaim must hand off:
        /// removed plus rejected entry ids. `Some` only in `Ready`/`Rebinding`.
        pub(crate) fn retired_entry_count(&self) -> Option<usize> {
            if !matches!(self.phase, Phase::Ready | Phase::Rebinding) {
                return None;
            }
            Some(
                self.removed_ids
                    .len()
                    .saturating_add(self.rejected_ids.len()),
            )
        }

        pub(crate) fn required_bytes(&self) -> Option<usize> {
            self.required
        }

        fn check_pool(
            &self,
            selection: &ConservativePinSelection,
            reserve: &SemanticResourceReserver,
        ) -> Result<(), GraphRefusal> {
            if !reserve.covers(&selection.storage, 0)
                || self
                    .header
                    .as_ref()
                    .is_some_and(|lease| !reserve.covers(lease, 0))
                || self
                    .backing
                    .as_ref()
                    .is_some_and(|lease| !reserve.covers(lease, 0))
                || self
                    .claim_backing
                    .as_ref()
                    .is_some_and(|lease| !reserve.covers(lease, 0))
            {
                return Err(GraphRefusal::Identity);
            }
            Ok(())
        }

        fn keep_after_retirement(&self, id: PinnedObjectId) -> bool {
            !self.removed_ids.contains(&id) || self.retained_ids.contains(&id)
        }

        fn output_mut(&mut self) -> Result<&mut PinnedObjects, GraphRefusal> {
            self.output.as_mut().ok_or(GraphRefusal::Identity)
        }

        fn next_phase(&mut self, next: Phase) {
            self.phase = next;
            self.last_id = None;
            self.last_view = None;
            self.active_view = None;
            self.last_key = None;
            self.index = 0;
            self.bucket = 0;
        }

        fn initial_bound(
            source: &PinnedObjects,
            selection: &ConservativePinSelection,
        ) -> Result<usize, GraphRefusal> {
            let mut total = std::mem::size_of::<Self>() + OWNED_ALLOCATION_PADDING;
            add(
                &mut total,
                tree::<PinnedObjectId, Entry>(source.by_id.len())?,
            )?;
            add(
                &mut total,
                tree::<RawObjectInstance, PinnedObjectId>(source.raw_to_id.len())?,
            )?;
            add(
                &mut total,
                tree::<ProcessViewId, ViewClaims>(source.ownership.len())?,
            )?;
            add(
                &mut total,
                tree::<ProcessViewId, BTreeSet<RawObjectInstance>>(source.raw_ownership.len())?,
            )?;
            let keys = source
                .ambiguous_keys
                .len()
                .checked_add(selection.rejected.len())
                .ok_or(GraphRefusal::Overflow)?;
            add(
                &mut total,
                tree::<ObjectKey, ()>(
                    source
                        .rejected_keys
                        .len()
                        .checked_add(selection.rejected.len())
                        .ok_or(GraphRefusal::Overflow)?,
                )?,
            )?;
            add(&mut total, tree::<ObjectKey, ()>(keys)?)?;
            add(
                &mut total,
                tree::<ObjectKey, ()>(
                    source
                        .ambiguity_published
                        .len()
                        .checked_add(keys)
                        .ok_or(GraphRefusal::Overflow)?,
                )?,
            )?;
            add(&mut total, bytes_for::<Skipped>(keys)?)?;
            add(
                &mut total,
                keys.checked_mul(
                    AMBIGUOUS_SUBJECT.len() + AMBIGUOUS_REASON.len() + 2 * OWNED_ALLOCATION_PADDING,
                )
                .ok_or(GraphRefusal::Overflow)?,
            )?;
            // Removed/retained/rejected ID indexes, manifest raw aliases, and
            // paid raw resume/output scratch can coexist with the output.
            add(&mut total, tree::<PinnedObjectId, ()>(source.by_id.len())?)?;
            add(
                &mut total,
                tree::<PinnedObjectId, ()>(source.raw_to_id.len())?,
            )?;
            add(
                &mut total,
                tree::<RawObjectInstance, ()>(source.raw_to_id.len())?,
            )?;
            Ok(total)
        }

        fn advance_owned_measure(
            &mut self,
            source: &PinnedObjects,
            reserve: &SemanticResourceReserver,
        ) -> Result<(), GraphRefusal> {
            if let Some(view) = self.active_view {
                let originals = source
                    .raw_ownership
                    .get(&view)
                    .ok_or(GraphRefusal::SourceChanged)?;
                let next = next_set(originals, self.walker.after());
                match self.walker.advance(next, reserve, true)? {
                    WalkStep::Progress => {}
                    WalkStep::Item => {
                        let raw = &self.walker.last.as_ref().ok_or(GraphRefusal::Identity)?.raw;
                        let bytes = text_bytes(&raw.path)?
                            .checked_mul(6)
                            .ok_or(GraphRefusal::Overflow)?;
                        add(&mut self.measured, bytes)?;
                    }
                    WalkStep::End => {
                        if self.walker.release_one() {
                            self.walker = RawWalker::default();
                            self.last_view = Some(view);
                            self.active_view = None;
                            self.phase = Phase::MeasureOwnedRows;
                        }
                    }
                }
            } else {
                return Err(GraphRefusal::Identity);
            }
            Ok(())
        }

        fn advance_claim_index(
            &mut self,
            source: &PinnedObjects,
            selection: &ConservativePinSelection,
        ) -> Result<(), GraphRefusal> {
            if let Some(view) = self.active_view {
                let claims = source
                    .ownership
                    .get(&view)
                    .ok_or(GraphRefusal::SourceChanged)?;
                if let Some(id) = claim_id(claims, self.bucket, self.index) {
                    if selection.retires(source, view) {
                        self.removed_ids.insert(id);
                    } else {
                        self.retained_ids.insert(id);
                    }
                    self.index += 1;
                } else if self.bucket < 2 {
                    self.bucket += 1;
                    self.index = 0;
                } else {
                    self.last_view = Some(view);
                    self.active_view = None;
                    self.bucket = 0;
                    self.index = 0;
                }
            } else if let Some((view, _)) = next_map(&source.ownership, self.last_view.as_ref()) {
                self.active_view = Some(*view);
                if selection.retires(source, *view) {
                    self.retired_count = self
                        .retired_count
                        .checked_add(1)
                        .ok_or(GraphRefusal::Overflow)?;
                }
            } else {
                self.next_phase(Phase::IndexManifest);
            }
            Ok(())
        }

        fn advance_raw_index(
            &mut self,
            source: &PinnedObjects,
            selection: &ConservativePinSelection,
            reserve: &SemanticResourceReserver,
            manifest: bool,
        ) -> Result<(), GraphRefusal> {
            if !manifest && self.active_view.is_none() {
                if let Some((view, _)) = next_map(&source.raw_ownership, self.last_view.as_ref()) {
                    self.active_view = Some(*view);
                } else {
                    self.next_phase(Phase::Classify);
                }
                return Ok(());
            }
            if self.raw_action {
                let raw = self.walker.after().ok_or(GraphRefusal::Identity)?;
                if let Some(copy) = copy_raw(&mut self.raw_copy, raw) {
                    if manifest
                        || !selection
                            .retires(source, self.active_view.ok_or(GraphRefusal::Identity)?)
                    {
                        self.retained_raws.insert(copy);
                    } else {
                        self.removed_raws.insert(copy);
                    }
                    self.raw_action = false;
                }
                return Ok(());
            }
            let next = if manifest {
                next_map(&source.raw_to_id, self.walker.after()).map(|(raw, _)| raw)
            } else {
                next_set(
                    source
                        .raw_ownership
                        .get(&self.active_view.ok_or(GraphRefusal::Identity)?)
                        .ok_or(GraphRefusal::SourceChanged)?,
                    self.walker.after(),
                )
            };
            match self.walker.advance(next, reserve, false)? {
                WalkStep::Progress => {}
                WalkStep::Item => {
                    let raw = self.walker.after().ok_or(GraphRefusal::Identity)?;
                    if !manifest || raw.mount_namespace.is_none() {
                        if manifest {
                            let id = *source
                                .raw_to_id
                                .get(raw)
                                .ok_or(GraphRefusal::SourceChanged)?;
                            self.retained_ids.insert(id);
                        }
                        self.raw_action = true;
                    }
                }
                WalkStep::End => {
                    if self.walker.release_one() {
                        self.walker = RawWalker::default();
                        if manifest {
                            self.next_phase(Phase::IndexRaws);
                        } else {
                            self.last_view = self.active_view.take();
                        }
                    }
                }
            }
            Ok(())
        }

        fn advance_raw_output(
            &mut self,
            source: &PinnedObjects,
            selection: &ConservativePinSelection,
            reserve: &SemanticResourceReserver,
            owned: bool,
        ) -> Result<(), GraphRefusal> {
            if owned && self.active_view.is_none() {
                if let Some((view, _)) = next_map(&source.raw_ownership, self.last_view.as_ref()) {
                    if selection.retires(source, *view) {
                        self.last_view = Some(*view);
                    } else {
                        self.active_view = Some(*view);
                        self.output_mut()?
                            .raw_ownership
                            .insert(*view, BTreeSet::new());
                    }
                } else {
                    self.next_phase(Phase::Rejected);
                }
                return Ok(());
            }
            if self.raw_action {
                let raw = self.walker.after().ok_or(GraphRefusal::Identity)?;
                if let Some(copy) = copy_raw(&mut self.raw_copy, raw) {
                    if owned {
                        let view = self.active_view.ok_or(GraphRefusal::Identity)?;
                        self.output_mut()?
                            .raw_ownership
                            .get_mut(&view)
                            .ok_or(GraphRefusal::Identity)?
                            .insert(copy);
                    } else {
                        let id = *source
                            .raw_to_id
                            .get(raw)
                            .ok_or(GraphRefusal::SourceChanged)?;
                        self.output_mut()?.raw_to_id.insert(copy, id);
                    }
                    self.raw_action = false;
                }
                return Ok(());
            }
            let next = if owned {
                next_set(
                    source
                        .raw_ownership
                        .get(&self.active_view.ok_or(GraphRefusal::Identity)?)
                        .ok_or(GraphRefusal::SourceChanged)?,
                    self.walker.after(),
                )
            } else {
                next_map(&source.raw_to_id, self.walker.after()).map(|(raw, _)| raw)
            };
            match self.walker.advance(next, reserve, false)? {
                WalkStep::Progress => {}
                WalkStep::Item => {
                    let raw = self.walker.after().ok_or(GraphRefusal::Identity)?;
                    let keep = if owned {
                        !selection.rejected.contains(&raw.key)
                    } else {
                        let id = *source
                            .raw_to_id
                            .get(raw)
                            .ok_or(GraphRefusal::SourceChanged)?;
                        self.keep_after_retirement(id)
                            && !self.rejected_ids.contains(&id)
                            && !selection.rejected.contains(&raw.key)
                            && (!self.removed_raws.contains(raw)
                                || self.retained_raws.contains(raw))
                    };
                    self.raw_action = keep;
                }
                WalkStep::End => {
                    if self.walker.release_one() {
                        self.walker = RawWalker::default();
                        if owned {
                            self.last_view = self.active_view.take();
                        } else {
                            self.next_phase(Phase::Ownership);
                        }
                    }
                }
            }
            Ok(())
        }

        fn advance_ownership(
            &mut self,
            source: &PinnedObjects,
            selection: &ConservativePinSelection,
        ) -> Result<(), GraphRefusal> {
            if let Some((view, copied)) = &mut self.claims {
                let original = source
                    .ownership
                    .get(view)
                    .ok_or(GraphRefusal::SourceChanged)?;
                if let Some(id) = claim_id(original, self.bucket, self.index) {
                    if !self.rejected_ids.contains(&id) {
                        match self.bucket {
                            0 => copied.tables.push(id),
                            1 => copied.targets.push(original.targets[self.index]),
                            _ => copied.pins.push(id),
                        }
                    }
                    self.index += 1;
                } else if self.bucket < 2 {
                    self.bucket += 1;
                    self.index = 0;
                } else {
                    let (view, copied) = self.claims.take().ok_or(GraphRefusal::Identity)?;
                    self.output_mut()?.ownership.insert(view, copied);
                    self.last_view = Some(view);
                    self.bucket = 0;
                    self.index = 0;
                }
            } else if let Some((view, claims)) =
                next_map(&source.ownership, self.last_view.as_ref())
            {
                if selection.retires(source, *view) {
                    self.last_view = Some(*view);
                } else {
                    self.claims = Some((
                        *view,
                        ViewClaims {
                            tables: Vec::with_capacity(claims.tables.len()),
                            targets: Vec::with_capacity(claims.targets.len()),
                            pins: Vec::with_capacity(claims.pins.len()),
                        },
                    ));
                }
            } else {
                self.next_phase(Phase::RawOwnership);
            }
            Ok(())
        }

        fn advance_sets(
            &mut self,
            source: &PinnedObjects,
            selection: &ConservativePinSelection,
        ) -> Result<(), GraphRefusal> {
            let original = match self.phase {
                Phase::Rejected => &source.rejected_keys,
                Phase::Ambiguous => &source.ambiguous_keys,
                Phase::Published => &source.ambiguity_published,
                Phase::ApplyRejected => &selection.rejected,
                _ => return Err(GraphRefusal::Identity),
            };
            if let Some(key) = next_set(original, self.last_key.as_ref()).copied() {
                self.last_key = Some(key);
                match self.phase {
                    Phase::Rejected | Phase::ApplyRejected => {
                        self.output_mut()?.rejected_keys.insert(key);
                    }
                    Phase::Ambiguous => {
                        self.output_mut()?.ambiguous_keys.insert(key);
                    }
                    Phase::Published => {
                        self.output_mut()?.ambiguity_published.insert(key);
                    }
                    _ => return Err(GraphRefusal::Identity),
                }
                if self.phase == Phase::ApplyRejected && source.rejected_keys.contains(&key) {
                    self.output_mut()?.ambiguous_keys.insert(key);
                }
            } else {
                self.next_phase(match self.phase {
                    Phase::Rejected => Phase::Ambiguous,
                    Phase::Ambiguous => Phase::Published,
                    Phase::Published => Phase::ApplyRejected,
                    _ => Phase::Publish,
                });
            }
            Ok(())
        }

        fn advance(
            &mut self,
            source: &PinnedObjects,
            selection: &ConservativePinSelection,
            reserve: &SemanticResourceReserver,
        ) -> Result<(), GraphRefusal> {
            match self.phase {
                Phase::New => {
                    let fence = SourceFence::new(source, selection)?;
                    let measured = Self::initial_bound(source, selection)?;
                    let header = reserve
                        .reserve(std::mem::size_of::<Self>() + OWNED_ALLOCATION_PADDING)
                        .map_err(GraphRefusal::Storage)?;
                    self.fence = Some(fence);
                    self.header = Some(header);
                    self.measured = measured;
                    self.phase = Phase::MeasureEntries;
                }
                Phase::MeasureEntries => {
                    if let Some((id, entry)) = next_map(&source.by_id, self.last_id.as_ref()) {
                        self.last_id = Some(*id);
                        for text in [&entry.raw.path, &entry.path, &entry.sha256] {
                            add(
                                &mut self.measured,
                                text.capacity()
                                    .checked_add(OWNED_ALLOCATION_PADDING)
                                    .ok_or(GraphRefusal::Overflow)?,
                            )?;
                        }
                        if let Some(text) = &entry.build_id {
                            add(
                                &mut self.measured,
                                text.capacity()
                                    .checked_add(OWNED_ALLOCATION_PADDING)
                                    .ok_or(GraphRefusal::Overflow)?,
                            )?;
                        }
                        // Shared backing can become uniquely owned during
                        // reclamation; keep its complete nested envelope paid.
                        add(
                            &mut self.measured,
                            bytes_for::<(String, u64)>(entry.exports.len())?,
                        )?;
                        self.index = 0;
                        self.phase = Phase::MeasureExports;
                    } else {
                        self.next_phase(Phase::MeasureClaims);
                    }
                }
                Phase::MeasureExports => {
                    let old = source
                        .by_id
                        .get(&self.last_id.ok_or(GraphRefusal::Identity)?)
                        .ok_or(GraphRefusal::SourceChanged)?;
                    if let Some((text, _)) = old.exports.get(self.index) {
                        add(
                            &mut self.measured,
                            text.capacity()
                                .checked_add(OWNED_ALLOCATION_PADDING)
                                .ok_or(GraphRefusal::Overflow)?,
                        )?;
                        self.index += 1;
                    } else {
                        self.phase = Phase::MeasureEntries;
                    }
                }
                Phase::MeasureClaims => {
                    if let Some((view, claims)) =
                        next_map(&source.ownership, self.last_view.as_ref())
                    {
                        self.last_view = Some(*view);
                        let count = claims
                            .tables
                            .len()
                            .checked_add(claims.targets.len())
                            .and_then(|sum| sum.checked_add(claims.pins.len()))
                            .ok_or(GraphRefusal::Overflow)?;
                        add(
                            &mut self.measured,
                            bytes_for::<PinnedObjectId>(claims.tables.capacity())?,
                        )?;
                        add(
                            &mut self.measured,
                            bytes_for::<(PinnedObjectId, u64)>(claims.targets.capacity())?,
                        )?;
                        add(
                            &mut self.measured,
                            bytes_for::<PinnedObjectId>(claims.pins.capacity())?,
                        )?;
                        add(
                            &mut self.measured,
                            tree::<PinnedObjectId, ()>(count)?
                                .checked_mul(2)
                                .ok_or(GraphRefusal::Overflow)?,
                        )?;
                    } else {
                        self.next_phase(Phase::MeasureRaws);
                    }
                }
                Phase::MeasureRaws => {
                    let next = next_map(&source.raw_to_id, self.walker.after()).map(|(raw, _)| raw);
                    match self.walker.advance(next, reserve, true)? {
                        WalkStep::Progress => {}
                        WalkStep::Item => {
                            let raw = &self.walker.last.as_ref().ok_or(GraphRefusal::Identity)?.raw;
                            let bytes = text_bytes(&raw.path)?
                                .checked_mul(6)
                                .ok_or(GraphRefusal::Overflow)?;
                            add(&mut self.measured, bytes)?;
                        }
                        WalkStep::End => {
                            if self.walker.release_one() {
                                self.walker = RawWalker::default();
                                self.next_phase(Phase::MeasureOwnedRows);
                            }
                        }
                    }
                }
                Phase::MeasureOwnedRows => {
                    if let Some((view, raws)) =
                        next_map(&source.raw_ownership, self.last_view.as_ref())
                    {
                        add(
                            &mut self.measured,
                            tree::<RawObjectInstance, ()>(raws.len())?
                                .checked_mul(3)
                                .ok_or(GraphRefusal::Overflow)?,
                        )?;
                        self.active_view = Some(*view);
                        self.phase = Phase::MeasureOwnedRaws;
                    } else {
                        self.required = Some(self.measured);
                        self.next_phase(Phase::Admit);
                    }
                }
                Phase::MeasureOwnedRaws => self.advance_owned_measure(source, reserve)?,
                Phase::Admit => {
                    let required = self.required.ok_or(GraphRefusal::Identity)?;
                    let header_bytes = std::mem::size_of::<Self>() + OWNED_ALLOCATION_PADDING;
                    let backing = reserve
                        .reserve(
                            required
                                .checked_sub(header_bytes)
                                .ok_or(GraphRefusal::Overflow)?,
                        )
                        .map_err(GraphRefusal::Storage)?;
                    self.backing = Some(backing);
                    let mut output = PinnedObjects::empty();
                    if output.copy_source.is_none() {
                        return Err(GraphRefusal::Identity);
                    }
                    output.next_id = source.next_id;
                    output.overlay_uncertain = source.overlay_uncertain;
                    output.changed.set(source.changed.get());
                    output.revision = source.revision;
                    output.copy_version = source.copy_version;
                    self.output = Some(output);
                    let skips = source
                        .ambiguous_keys
                        .len()
                        .checked_add(selection.rejected.len())
                        .ok_or(GraphRefusal::Overflow)?;
                    self.skipped = Vec::with_capacity(skips);
                    self.next_phase(Phase::IndexClaims);
                }
                Phase::IndexClaims => self.advance_claim_index(source, selection)?,
                Phase::IndexManifest => self.advance_raw_index(source, selection, reserve, true)?,
                Phase::IndexRaws => self.advance_raw_index(source, selection, reserve, false)?,
                Phase::Classify => {
                    if let Some((id, entry)) = next_map(&source.by_id, self.last_id.as_ref()) {
                        self.last_id = Some(*id);
                        if self.keep_after_retirement(*id)
                            && selection.rejected.contains(&entry.raw.key)
                        {
                            self.rejected_ids.insert(*id);
                            self.output_mut()?.ambiguous_keys.insert(entry.raw.key);
                        }
                    } else {
                        self.next_phase(Phase::Entries);
                    }
                }
                Phase::Entries => {
                    if let Some(copy) = &mut self.entry {
                        let original = source
                            .by_id
                            .get(&copy.id)
                            .ok_or(GraphRefusal::SourceChanged)?;
                        if copy.advance(original) {
                            let copy = self.entry.take().ok_or(GraphRefusal::Identity)?;
                            self.output_mut()?.by_id.insert(copy.id, copy.entry);
                        }
                    } else if let Some((id, old)) = next_map(&source.by_id, self.last_id.as_ref()) {
                        self.last_id = Some(*id);
                        if self.keep_after_retirement(*id) && !self.rejected_ids.contains(id) {
                            self.entry = Some(EntryCopy::new(*id, old));
                        }
                    } else {
                        self.next_phase(Phase::RawMap);
                    }
                }
                Phase::RawMap => self.advance_raw_output(source, selection, reserve, false)?,
                Phase::Ownership => self.advance_ownership(source, selection)?,
                Phase::RawOwnership => self.advance_raw_output(source, selection, reserve, true)?,
                Phase::Rejected | Phase::Ambiguous | Phase::Published | Phase::ApplyRejected => {
                    self.advance_sets(source, selection)?
                }
                Phase::Publish => {
                    let next = next_set(
                        &self
                            .output
                            .as_ref()
                            .ok_or(GraphRefusal::Identity)?
                            .ambiguous_keys,
                        self.last_key.as_ref(),
                    )
                    .copied();
                    if let Some(key) = next {
                        self.last_key = Some(key);
                        if self.output_mut()?.ambiguity_published.insert(key) {
                            self.skipped.push(ambiguous_identity_skip());
                        }
                    } else {
                        let revision = source
                            .revision
                            .checked_add(self.retired_count)
                            .and_then(|rev| {
                                rev.checked_add(u64::try_from(selection.rejected.len()).ok()?)
                            })
                            .filter(|rev| *rev < u64::MAX)
                            .ok_or(GraphRefusal::SourceChanged)?;
                        self.output_mut()?.revision = revision;
                        self.phase = Phase::Ready;
                    }
                }
                Phase::Ready => {}
                Phase::Rebinding
                | Phase::RebindAborted
                | Phase::Installed
                | Phase::Reclaim
                | Phase::Reclaimed => {
                    return Err(GraphRefusal::Cancelled);
                }
            }
            Ok(())
        }

        /// Reclaims one leaf/node operation per credit. An unknown shared/Weak
        /// export owner refuses while retaining the paid original, then resumes
        /// with an actual live source alias or exclusive Arc::get_mut.
        pub(crate) fn reclaim(
            &mut self,
            source: Option<&PinnedObjects>,
            selection: &ConservativePinSelection,
            reserve: &SemanticResourceReserver,
            work: usize,
        ) -> Result<GraphStep, GraphRefusal> {
            if work == 0 {
                return Ok(GraphStep::Yielded);
            }
            if self.rebind_owner.is_some() || self.rebind_old_pins.is_some() {
                return Err(GraphRefusal::Identity);
            }
            self.check_pool(selection, reserve)?;
            if let Some(fence) = self.fence {
                if fence.selection != selection.identity {
                    return Err(GraphRefusal::Identity);
                }
                if let Some(source) = source {
                    fence.check(source, selection)?;
                }
            }
            if self.phase == Phase::Reclaimed {
                return Ok(GraphStep::Ready);
            }
            self.phase = Phase::Reclaim;
            for _ in 0..work {
                self.reclaim_one(source, None, reserve)?;
                if self.phase == Phase::Reclaimed {
                    return Ok(GraphStep::Ready);
                }
            }
            Ok(GraphStep::Advanced)
        }

        /// O(1) install sink: swaps the Ready copy (or the Rebinding loaned
        /// output) into the canonical, records the installed identity, and
        /// moves the output payment into the returned backing. The cursor's
        /// output now holds the old canonical for `reclaim_installed`.
        pub(crate) fn install_ready(
            &mut self,
            canonical: &mut PinnedObjects,
        ) -> Result<InstalledPinsBacking, GraphRefusal> {
            match self.phase {
                Phase::Ready if self.rebind_owner.is_none() => {}
                Phase::Rebinding if self.rebind_owner.is_some() => {}
                Phase::RebindAborted | Phase::Reclaim | Phase::Reclaimed | Phase::Installed => {
                    return Err(GraphRefusal::Cancelled);
                }
                _ => return Err(GraphRefusal::Identity),
            }
            let output = self.output.as_mut().ok_or(GraphRefusal::Identity)?;
            std::mem::swap(output, canonical);
            self.installed = Some(canonical.copy_source.ok_or(GraphRefusal::Identity)?);
            self.phase = Phase::Installed;
            Ok(InstalledPinsBacking {
                claim_backing: self.claim_backing.take(),
                backing: self.backing.take(),
                header: self.header.take(),
            })
        }

        /// Reclaims the old canonical (held in `output` since `install_ready`)
        /// against the live installed canonical: live-aliased files are
        /// released, absent files move into the handoff, never dropped.
        pub(crate) fn reclaim_installed(
            &mut self,
            live: &PinnedObjects,
            selection: &ConservativePinSelection,
            handoff: &mut RetiredFileHandoff,
            reserve: &SemanticResourceReserver,
            work: usize,
        ) -> Result<GraphStep, GraphRefusal> {
            if work == 0 {
                return Ok(GraphStep::Yielded);
            }
            if self.phase == Phase::Reclaimed {
                return Ok(GraphStep::Ready);
            }
            if self.phase != Phase::Installed
                || live.copy_source != self.installed
                || self.rebind_owner.is_some()
            {
                return Err(GraphRefusal::Identity);
            }
            self.check_pool(selection, reserve)?;
            for _ in 0..work {
                self.reclaim_one(Some(live), Some(&mut *handoff), reserve)?;
                if self.phase == Phase::Reclaimed {
                    return Ok(GraphStep::Ready);
                }
            }
            Ok(GraphStep::Advanced)
        }

        fn reclaim_one(
            &mut self,
            source: Option<&PinnedObjects>,
            handoff: Option<&mut RetiredFileHandoff>,
            reserve: &SemanticResourceReserver,
        ) -> Result<(), GraphRefusal> {
            if let Some(entry) = &mut self.reclaim_entry {
                let done = match handoff {
                    Some(handoff) => entry.advance_installed(source, handoff, reserve)?,
                    None => entry.advance(source)?,
                };
                if done {
                    self.reclaim_entry = None;
                }
                return Ok(());
            }
            if let Some(copy) = self.entry.take() {
                self.reclaim_entry = Some(EntryReclaim::new(copy.id, copy.entry));
                return Ok(());
            }
            match self.reclaim_phase {
                0 => {
                    if !self.walker.release_one() {
                        return Ok(());
                    }
                    self.reclaim_phase += 1;
                }
                1 => {
                    if self.raw_copy.take().is_some() {
                        return Ok(());
                    }
                    self.reclaim_phase += 1;
                }
                2 => {
                    if let Some((_, claims)) = &mut self.claims {
                        if claims.tables.capacity() > 0 {
                            drop(std::mem::take(&mut claims.tables));
                        } else if claims.targets.capacity() > 0 {
                            drop(std::mem::take(&mut claims.targets));
                        } else if claims.pins.capacity() > 0 {
                            drop(std::mem::take(&mut claims.pins));
                        } else {
                            self.claims = None;
                        }
                        return Ok(());
                    }
                    self.reclaim_phase = self.after_claim_reclaim;
                    self.after_claim_reclaim = 3;
                }
                3 => {
                    if let Some((id, entry)) =
                        self.output.as_mut().and_then(|pins| pins.by_id.pop_first())
                    {
                        self.reclaim_entry = Some(EntryReclaim::new(id, entry));
                    } else {
                        if let Some(pins) = &mut self.output {
                            drop(std::mem::take(&mut pins.by_id));
                        }
                        self.reclaim_phase += 1;
                    }
                }
                4 => {
                    if let Some(pins) = &mut self.output {
                        if pins.raw_to_id.pop_first().is_some() {
                            return Ok(());
                        }
                        drop(std::mem::take(&mut pins.raw_to_id));
                    }
                    self.reclaim_phase += 1;
                }
                5 => {
                    if self.claims.is_none()
                        && let Some(pair) = self
                            .output
                            .as_mut()
                            .and_then(|pins| pins.ownership.pop_first())
                    {
                        self.claims = Some(pair);
                        self.reclaim_phase = 2;
                        // Return to ownership, rather than restart by-id/raws,
                        // after this row's three primitive Vec leaves.
                        self.after_claim_reclaim = 5;
                        return Ok(());
                    }
                    if let Some(pins) = &mut self.output {
                        drop(std::mem::take(&mut pins.ownership));
                    }
                    self.reclaim_phase += 1;
                }
                6 => {
                    if let Some(pins) = &mut self.output
                        && let Some(view) =
                            pins.raw_ownership.first_key_value().map(|(view, _)| *view)
                    {
                        let raws = pins
                            .raw_ownership
                            .get_mut(&view)
                            .ok_or(GraphRefusal::Identity)?;
                        if raws.pop_first().is_none() {
                            // The inner set is now actually empty. Removing the
                            // outer node cannot hide another raw/String drop.
                            pins.raw_ownership.remove(&view);
                        }
                        return Ok(());
                    }
                    if let Some(pins) = &mut self.output {
                        drop(std::mem::take(&mut pins.raw_ownership));
                    }
                    self.reclaim_phase += 1;
                }
                7..=9 => {
                    if let Some(pins) = &mut self.output {
                        let set = match self.reclaim_phase {
                            7 => &mut pins.rejected_keys,
                            8 => &mut pins.ambiguous_keys,
                            _ => &mut pins.ambiguity_published,
                        };
                        if set.pop_first().is_some() {
                            return Ok(());
                        }
                        drop(std::mem::take(set));
                    }
                    self.reclaim_phase += 1;
                }
                10..=12 => {
                    let set = match self.reclaim_phase {
                        10 => &mut self.removed_ids,
                        11 => &mut self.retained_ids,
                        _ => &mut self.rejected_ids,
                    };
                    if set.pop_first().is_none() {
                        // len==0 can still retain a real root allocation.
                        drop(std::mem::take(set));
                        self.reclaim_phase += 1;
                    }
                }
                13..=14 => {
                    let set = if self.reclaim_phase == 13 {
                        &mut self.removed_raws
                    } else {
                        &mut self.retained_raws
                    };
                    if set.pop_first().is_none() {
                        // len==0 can still retain a real root allocation.
                        drop(std::mem::take(set));
                        self.reclaim_phase += 1;
                    }
                }
                15 => {
                    if let Some(skip) = &mut self.skipped_leaf {
                        if skip.subject.capacity() > 0 {
                            drop(std::mem::take(&mut skip.subject));
                        } else if skip.reason.capacity() > 0 {
                            drop(std::mem::take(&mut skip.reason));
                        } else {
                            self.skipped_leaf = None;
                        }
                    } else if let Some(skip) = self.skipped.pop() {
                        self.skipped_leaf = Some(skip);
                    } else {
                        self.reclaim_phase += 1;
                    }
                }
                16 => {
                    drop(std::mem::take(&mut self.skipped));
                    self.reclaim_phase += 1;
                }
                17 => {
                    self.output = None;
                    self.reclaim_phase += 1;
                }
                18 => {
                    self.claim_backing = None;
                    self.reclaim_phase += 1;
                }
                19 => {
                    self.backing = None;
                    self.reclaim_phase += 1;
                }
                _ => {
                    self.header = None;
                    self.phase = Phase::Reclaimed;
                }
            }
            Ok(())
        }

        #[cfg(test)]
        pub(super) fn retained_reclaim_file_for_test(
            &self,
            id: PinnedObjectId,
        ) -> Option<(u8, Option<RawFd>)> {
            let entry = self.reclaim_entry.as_ref().filter(|entry| entry.id == id)?;
            Some((
                entry.field,
                entry.file.as_ref().map(|file| file.as_raw_fd()),
            ))
        }

        #[cfg(test)]
        pub(super) fn retained_exports_for_test(
            &self,
            id: PinnedObjectId,
        ) -> Option<&[(String, u64)]> {
            if let Some(entry) = &self.reclaim_entry
                && entry.id == id
            {
                return entry.exports.as_deref();
            }
            self.output
                .as_ref()?
                .by_id
                .get(&id)
                .map(|entry| entry.exports.as_ref())
        }

        #[cfg(test)]
        pub(super) fn installed_state_for_test(&self) -> (bool, bool) {
            (self.phase == Phase::Installed, self.rebind_owner.is_none())
        }

        #[cfg(test)]
        pub(super) fn installed_output_for_test(&self) -> Option<&PinnedObjects> {
            (self.phase == Phase::Installed)
                .then_some(self.output.as_ref())
                .flatten()
        }
    }

    /// Files-only retirement handoff: old-canonical files with no live alias
    /// move here during installed reclaim instead of being dropped. The lane
    /// closes them after the same Session's joined terminal detach via
    /// `close_some`; chained graphs link through `prev`.
    #[derive(Debug)]
    pub(crate) struct RetiredFileHandoff {
        files: Vec<Arc<std::fs::File>>,
        pub(crate) prev: Option<Box<RetiredFileHandoff>>,
        lease: Option<ResourceLease>,
        reserved: usize,
    }

    impl RetiredFileHandoff {
        /// One boxed handoff plus an exact `files`-slot Vec, with padding.
        pub(crate) fn bytes(files: usize) -> usize {
            std::mem::size_of::<Self>()
                .saturating_add(OWNED_ALLOCATION_PADDING)
                .saturating_add(files.saturating_mul(std::mem::size_of::<Arc<std::fs::File>>()))
                .saturating_add(OWNED_ALLOCATION_PADDING)
        }

        /// One reservation covering the box and the exact-capacity Vec.
        pub(crate) fn reserve(
            files: usize,
            reserve: &SemanticResourceReserver,
        ) -> Result<Box<Self>, GraphRefusal> {
            let lease = reserve
                .reserve(Self::bytes(files))
                .map_err(GraphRefusal::Storage)?;
            Ok(Box::new(Self {
                files: Vec::with_capacity(files),
                prev: None,
                lease: Some(lease),
                reserved: files,
            }))
        }

        /// Drops at most `max` file shares, head first then the `prev` chain.
        /// Returns true only when every link is empty.
        pub(crate) fn close_some(&mut self, max: usize) -> bool {
            let head = self.files.len().min(max);
            self.files.drain(..head);
            let budget = max - head;
            if budget > 0
                && let Some(prev) = self.prev.as_mut()
            {
                prev.close_some(budget);
            }
            self.is_empty()
        }

        fn is_empty(&self) -> bool {
            self.files.is_empty() && self.prev.as_ref().is_none_or(|prev| prev.is_empty())
        }

        fn push(&mut self, file: &Arc<std::fs::File>) -> Result<(), ()> {
            if self.files.len() >= self.reserved {
                return Err(());
            }
            self.files.push(Arc::clone(file));
            Ok(())
        }

        #[cfg(test)]
        pub(super) fn len_for_test(&self) -> usize {
            self.files.len()
        }
    }

    fn claim_id(claims: &ViewClaims, bucket: u8, index: usize) -> Option<PinnedObjectId> {
        match bucket {
            0 => claims.tables.get(index).copied(),
            1 => claims.targets.get(index).map(|(id, _)| *id),
            _ => claims.pins.get(index).copied(),
        }
    }

    fn copy_raw(
        copy: &mut Option<RawObjectInstance>,
        original: &RawObjectInstance,
    ) -> Option<RawObjectInstance> {
        if copy.is_none() {
            *copy = Some(RawObjectInstance {
                mount_namespace: original.mount_namespace,
                key: original.key,
                path: String::with_capacity(original.path.len()),
            });
            return None;
        }
        if copy_text(&mut copy.as_mut()?.path, &original.path) {
            copy.take()
        } else {
            None
        }
    }

    impl PinnedObjects {
        pub(crate) fn poll_conservative_copy(
            &self,
            cursor: &mut PinnedConservativeCursor,
            selection: &ConservativePinSelection,
            reserve: &SemanticResourceReserver,
            work: usize,
        ) -> Result<GraphStep, GraphRefusal> {
            if work == 0 {
                return Ok(GraphStep::Yielded);
            }
            cursor.check_pool(selection, reserve)?;
            if let Some(fence) = cursor.fence {
                fence.check(self, selection)?;
            } else {
                SourceFence::new(self, selection)?;
            }
            if matches!(
                cursor.phase,
                Phase::Rebinding | Phase::RebindAborted | Phase::Reclaim | Phase::Reclaimed
            ) {
                return Err(GraphRefusal::Cancelled);
            }
            for _ in 0..work {
                cursor.advance(self, selection, reserve)?;
                if cursor.phase == Phase::Ready {
                    return Ok(GraphStep::Ready);
                }
            }
            Ok(GraphStep::Advanced)
        }
    }

    /// Deallocates the SAME unique slice allocation without an O(N) typed Drop
    /// loop. Only the drained `(String,u64)` path above and resource-free test
    /// probes may call this. No ManuallyDrop value is stored or exposed.
    ///
    /// # Safety
    /// Caller must immediately establish actual exclusive Arc::get_mut/noWeak,
    /// drain ALL owned element resources (leaving valid bits), and transfer the
    /// original Arc without callback/observer/alias exposure. This function
    /// reconstructs exactly once with identical allocation, len, and Global.
    pub(super) unsafe fn deallocate_drained_unique_arc<T>(original: Arc<[T]>) {
        use std::mem::ManuallyDrop;
        // ManuallyDrop<T> has identical layout AND bit validity to T:
        // https://doc.rust-lang.org/std/mem/struct.ManuallyDrop.html
        // Arc::from_raw permits equal-size/alignment retyping of the original
        // Global allocation; slice pointer cast retains the exact length:
        // https://doc.rust-lang.org/std/sync/struct.Arc.html#method.from_raw
        let raw = Arc::into_raw(original);
        let raw = raw as *const [ManuallyDrop<T>];
        // SAFETY: caller's unique original, same size/alignment/metadata/Global,
        // valid elements, resources already individually disposed, one recovery.
        drop(unsafe { Arc::from_raw(raw) });
    }

    const _: () = {
        use std::mem::{ManuallyDrop, align_of, needs_drop, size_of};
        assert!(needs_drop::<(String, u64)>());
        assert!(!needs_drop::<ManuallyDrop<(String, u64)>>());
        assert!(size_of::<(String, u64)>() == size_of::<ManuallyDrop<(String, u64)>>());
        assert!(align_of::<(String, u64)>() == align_of::<ManuallyDrop<(String, u64)>>());
    };

    pub(crate) use scanned_rebind::{
        InstalledModulesBacking, RetainedScannedInputs, ScannedInputMeasure, ScannedRebindCursor,
    };

    mod scanned_rebind {
        use super::*;
        use crate::discovery::scan::{ScannedEntry, ScannedInterface, ScannedTable};

        static NEXT_SCANNED_INPUT: AtomicU64 = AtomicU64::new(0);
        const MODULE_MISSING: &str =
            "module has no comparable pinned identity; it was not attached";
        const MODULE_ABI: &str = "module decoder ABI disagrees with its retained pinned identity; its tables were not attached";
        const ENTRY_MISSING: &str =
            " could not be reconciled to a comparable pinned object; entry was not attached";
        const ENTRY_ABI: &str =
            " has a different target ABI from its provider; entry was not attached";

        /// Original owned rows plus actual payment, not proof of valid backing,
        /// admission or pin identity. Only positive-work preflight may take it.
        pub(crate) struct RetainedScannedInputs {
            rows: Vec<ScannedModule>,
            identity: PinCopyCacheId,
            storage: ResourceLease,
        }

        pub(crate) struct ScannedInputRefusal {
            rows: Vec<ScannedModule>,
            storage: ResourceLease,
        }

        impl std::fmt::Debug for ScannedInputRefusal {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("ScannedInputRefusal")
                    .field("rows", &self.rows.len())
                    .finish_non_exhaustive()
            }
        }

        impl ScannedInputRefusal {
            pub(crate) fn into_originals(self) -> (Vec<ScannedModule>, ResourceLease) {
                (self.rows, self.storage)
            }
        }

        impl RetainedScannedInputs {
            pub(crate) fn from_reserved_originals(
                rows: Vec<ScannedModule>,
                storage: ResourceLease,
            ) -> Result<Self, ScannedInputRefusal> {
                match mint_pin_copy_cache_id(&NEXT_SCANNED_INPUT) {
                    Some(identity) => Ok(Self {
                        rows,
                        identity,
                        storage,
                    }),
                    None => Err(ScannedInputRefusal { rows, storage }),
                }
            }

            pub(crate) fn into_originals(self) -> (Vec<ScannedModule>, ResourceLease) {
                (self.rows, self.storage)
            }

            #[cfg(test)]
            pub(crate) fn originals_for_test(&self) -> &[ScannedModule] {
                &self.rows
            }
            #[cfg(test)]
            pub(crate) fn original_capacity_for_test(&self) -> usize {
                self.rows.capacity()
            }
        }

        #[derive(Clone, Copy, Default)]
        struct Growth {
            tables: usize,
            targets: usize,
            pins: usize,
        }

        fn charge_text(text: &String) -> Result<usize, GraphRefusal> {
            text.capacity()
                .checked_add(OWNED_ALLOCATION_PADDING)
                .ok_or(GraphRefusal::Overflow)
        }

        fn normalization_bound(path: &str) -> Result<usize, GraphRefusal> {
            text_bytes(path)?
                .checked_add(bytes_for::<usize>(path.len() / 2 + 1)?)
                .ok_or(GraphRefusal::Overflow)
        }

        /// A Linux path-component cursor. Neither lookup nor measurement calls
        /// the allocating, whole-path ordinary normalization helper.
        struct Normalize {
            path: String,
            parents: Vec<usize>,
            start: usize,
            scan: usize,
            copying: Option<(usize, usize)>,
        }

        impl Normalize {
            fn new(original: &str) -> Option<Self> {
                if !original.starts_with('/') {
                    return None;
                }
                let mut path = String::with_capacity(original.len());
                path.push('/');
                Some(Self {
                    path,
                    parents: Vec::with_capacity(original.len() / 2 + 1),
                    start: 1,
                    scan: 1,
                    copying: None,
                })
            }

            fn advance(&mut self, original: &str) -> bool {
                if let Some((start, end)) = self.copying {
                    let mut next = start.saturating_add(TEXT_QUANTUM).min(end);
                    while !original.is_char_boundary(next) {
                        next -= 1;
                    }
                    self.path.push_str(&original[start..next]);
                    if next == end {
                        self.copying = None;
                        self.start = end + 1;
                        self.scan = end + 1;
                    } else {
                        self.copying = Some((next, end));
                    }
                    return false;
                }
                if self.start > original.len() {
                    return true;
                }
                let stop = self.scan.saturating_add(TEXT_QUANTUM).min(original.len());
                let slash = original.as_bytes()[self.scan..stop]
                    .iter()
                    .position(|byte| *byte == b'/');
                let end = match slash {
                    Some(offset) => self.scan + offset,
                    None if stop < original.len() => {
                        self.scan = stop;
                        return false;
                    }
                    None => original.len(),
                };
                let component = &original[self.start..end];
                match component {
                    "" | "." => {
                        self.start = end + 1;
                        self.scan = end + 1;
                    }
                    ".." => {
                        if let Some(parent) = self.parents.pop() {
                            self.path.truncate(parent);
                        }
                        self.start = end + 1;
                        self.scan = end + 1;
                    }
                    _ => {
                        self.parents.push(self.path.len());
                        if self.path.len() > 1 {
                            self.path.push('/');
                        }
                        self.copying = Some((self.start, end));
                    }
                }
                false
            }

            fn reclaim_one(&mut self) -> bool {
                if self.path.capacity() != 0 {
                    drop(std::mem::take(&mut self.path));
                    return false;
                }
                if self.parents.capacity() != 0 {
                    drop(std::mem::take(&mut self.parents));
                    return false;
                }
                true
            }
        }

        struct SkipCopy {
            skip: Skipped,
            stage: u8,
            prefix_done: usize,
            suffix_done: usize,
        }
        impl SkipCopy {
            fn new() -> Self {
                Self {
                    skip: Skipped {
                        subject: String::new(),
                        reason: String::new(),
                    },
                    stage: 0,
                    prefix_done: 0,
                    suffix_done: 0,
                }
            }
            fn advance(&mut self, subject: &str, prefix: &str, suffix: &str) -> bool {
                match self.stage {
                    0 => {
                        self.skip.subject = String::with_capacity(subject.len());
                        self.stage = 1;
                    }
                    1 => {
                        if copy_text(&mut self.skip.subject, subject) {
                            self.stage = 2;
                        }
                    }
                    2 => {
                        self.skip.reason = String::with_capacity(prefix.len() + suffix.len());
                        self.stage = 3;
                    }
                    3 => {
                        let mut end = self
                            .prefix_done
                            .saturating_add(TEXT_QUANTUM)
                            .min(prefix.len());
                        while !prefix.is_char_boundary(end) {
                            end -= 1;
                        }
                        self.skip.reason.push_str(&prefix[self.prefix_done..end]);
                        self.prefix_done = end;
                        if end == prefix.len() {
                            self.stage = 4;
                        }
                    }
                    4 => {
                        let mut end = self
                            .suffix_done
                            .saturating_add(TEXT_QUANTUM)
                            .min(suffix.len());
                        while !suffix.is_char_boundary(end) {
                            end -= 1;
                        }
                        self.skip.reason.push_str(&suffix[self.suffix_done..end]);
                        self.suffix_done = end;
                        if end == suffix.len() {
                            self.stage = 5;
                        }
                    }
                    _ => return true,
                }
                false
            }
        }

        fn reclaim_skip(skip: &mut Skipped) -> bool {
            if skip.subject.capacity() != 0 {
                drop(std::mem::take(&mut skip.subject));
                false
            } else if skip.reason.capacity() != 0 {
                drop(std::mem::take(&mut skip.reason));
                false
            } else {
                true
            }
        }

        struct TableDrain {
            table: ScannedTable,
            stage: u8,
            skip: Option<Skipped>,
        }
        impl TableDrain {
            fn new(table: ScannedTable) -> Self {
                Self {
                    table,
                    stage: 0,
                    skip: None,
                }
            }
            fn advance(&mut self) -> bool {
                match self.stage {
                    0 => {
                        if let Some(entry) = self.table.entries.pop() {
                            drop(entry.object_path);
                        } else {
                            drop(std::mem::take(&mut self.table.entries));
                            self.stage = 1;
                        }
                    }
                    1 => {
                        drop(std::mem::take(&mut self.table.null_entries));
                        self.stage = 2;
                    }
                    2 => {
                        if let Some(skip) = &mut self.skip {
                            if reclaim_skip(skip) {
                                self.skip = None;
                            }
                        } else if let Some(skip) = self.table.unpinned.pop() {
                            self.skip = Some(skip);
                        } else {
                            drop(std::mem::take(&mut self.table.unpinned));
                            self.stage = 3;
                        }
                    }
                    _ => return true,
                }
                false
            }
        }

        struct ModuleDrain {
            module: ScannedModule,
            stage: u8,
            table: Option<TableDrain>,
            interface: Option<ScannedInterface>,
        }
        impl ModuleDrain {
            fn new(module: ScannedModule) -> Self {
                Self {
                    module,
                    stage: 0,
                    table: None,
                    interface: None,
                }
            }
            fn advance(&mut self) -> bool {
                match self.stage {
                    0 => {
                        drop(std::mem::take(&mut self.module.path));
                        self.stage = 1;
                    }
                    1 => {
                        if self.module.exports.pop().is_none() {
                            drop(std::mem::take(&mut self.module.exports));
                            self.stage = 2;
                        }
                    }
                    2 => {
                        if let Some(table) = &mut self.table {
                            if table.advance() {
                                self.table = None;
                            }
                        } else if let Some(table) = self.module.tables.pop() {
                            self.table = Some(TableDrain::new(table));
                        } else {
                            drop(std::mem::take(&mut self.module.tables));
                            self.stage = 3;
                        }
                    }
                    3 => {
                        if let Some(interface) = &mut self.interface {
                            if interface.name_lossy.take().is_some() {
                                return false;
                            }
                            if interface.name_private.take().is_some() {
                                return false;
                            }
                            self.interface = None;
                        } else if let Some(interface) = self.module.interfaces.pop() {
                            self.interface = Some(interface);
                        } else {
                            drop(std::mem::take(&mut self.module.interfaces));
                            self.stage = 4;
                        }
                    }
                    _ => return true,
                }
                false
            }
        }

        #[derive(Clone, Copy, PartialEq, Eq)]
        enum BindPhase {
            New,
            MeasureInput,
            MeasureViews,
            MeasurePin,
            MeasurePinExports,
            Admit,
            Reset,
            Grow,
            NextModule,
            ProviderStart,
            ProviderNormalize,
            ProviderResolve,
            ModuleSkip,
            DiscardModule,
            TableStart,
            MoveSkips,
            NextEntry,
            EntryNormalize,
            EntryResolve,
            EntrySkip,
            EntrySkipCopy,
            DropEntry,
            FinishTable,
            ClaimTables,
            ClaimModule,
            ClaimEntries,
            FinishModule,
            Ready,
            Installed,
            Reclaim,
            Reclaimed,
        }

        #[derive(Clone, Copy)]
        struct BindFence {
            candidate: PinCopyCacheId,
            input: PinCopyCacheId,
            revision: u64,
            version: u64,
            changed: bool,
        }

        /// Stateful input measurer over scanned rows: one field group or
        /// element per `step` credit. The rebind cursor drives it during
        /// measurement; the Engine's RawCopy phase drives it directly. Call
        /// `step` repeatedly for one module until it returns true, then move
        /// to the next module.
        pub(crate) struct ScannedInputMeasure {
            bytes: usize,
            extra: usize,
            max_skips: usize,
            growth: BTreeMap<ProcessViewId, Growth>,
            table: usize,
            item: usize,
            stage: u8,
        }

        impl ScannedInputMeasure {
            /// Seeds the retained-input envelope for a row Vec of `rows`
            /// capacity: the wrapper plus the exact backing array charge.
            pub(crate) fn new(rows: usize) -> Result<Self, GraphRefusal> {
                Ok(Self {
                    bytes: std::mem::size_of::<RetainedScannedInputs>()
                        .checked_add(bytes_for::<ScannedModule>(rows)?)
                        .ok_or(GraphRefusal::Overflow)?,
                    extra: 0,
                    max_skips: 0,
                    growth: BTreeMap::new(),
                    table: 0,
                    item: 0,
                    stage: 0,
                })
            }

            fn empty() -> Self {
                Self {
                    bytes: 0,
                    extra: 0,
                    max_skips: 0,
                    growth: BTreeMap::new(),
                    table: 0,
                    item: 0,
                    stage: 0,
                }
            }

            /// Measures one field group or element of `source`; true when
            /// this module is fully measured.
            pub(crate) fn step(&mut self, source: &ScannedModule) -> Result<bool, GraphRefusal> {
                match self.stage {
                    0 => {
                        add(&mut self.bytes, charge_text(&source.path)?)?;
                        add(
                            &mut self.bytes,
                            bytes_for::<String>(source.exports.capacity())?,
                        )?;
                        add(
                            &mut self.bytes,
                            bytes_for::<ScannedTable>(source.tables.capacity())?,
                        )?;
                        add(
                            &mut self.bytes,
                            bytes_for::<ScannedInterface>(source.interfaces.capacity())?,
                        )?;
                        add(&mut self.extra, normalization_bound(&source.path)?)?;
                        add(
                            &mut self.extra,
                            bytes_for::<Vec<PinnedObjectId>>(source.tables.len())?,
                        )?;
                        add(&mut self.extra, text_bytes(&source.path)?)?;
                        add(&mut self.extra, text_bytes(MODULE_ABI)?)?;
                        self.max_skips = self
                            .max_skips
                            .checked_add(1)
                            .ok_or(GraphRefusal::Overflow)?;
                        let growth = self.growth.entry(source.view).or_default();
                        growth.tables = growth
                            .tables
                            .checked_add(source.tables.len())
                            .ok_or(GraphRefusal::Overflow)?;
                        growth.pins = growth.pins.checked_add(1).ok_or(GraphRefusal::Overflow)?;
                        self.item = 0;
                        self.stage = 1;
                        Ok(false)
                    }
                    1 => {
                        if let Some(text) = source.exports.get(self.item) {
                            add(&mut self.bytes, charge_text(text)?)?;
                            self.item += 1;
                            Ok(false)
                        } else {
                            self.item = 0;
                            self.stage = 2;
                            Ok(false)
                        }
                    }
                    2 => {
                        if let Some(interface) = source.interfaces.get(self.item) {
                            if let Some(text) = &interface.name_lossy {
                                add(&mut self.bytes, charge_text(text)?)?;
                            }
                            if let Some(bytes) = &interface.name_private {
                                add(&mut self.bytes, bytes_for::<u8>(bytes.capacity())?)?;
                            }
                            self.item += 1;
                            Ok(false)
                        } else {
                            self.table = 0;
                            self.stage = 3;
                            Ok(false)
                        }
                    }
                    3 => {
                        if let Some(table) = source.tables.get(self.table) {
                            add(
                                &mut self.bytes,
                                bytes_for::<ScannedEntry>(table.entries.capacity())?,
                            )?;
                            add(
                                &mut self.bytes,
                                bytes_for::<&'static str>(table.null_entries.capacity())?,
                            )?;
                            add(
                                &mut self.bytes,
                                bytes_for::<Skipped>(table.unpinned.capacity())?,
                            )?;
                            add(
                                &mut self.extra,
                                bytes_for::<ScannedEntry>(table.entries.len())?,
                            )?;
                            add(
                                &mut self.extra,
                                bytes_for::<PinnedObjectId>(table.entries.len())?,
                            )?;
                            let skips = table
                                .unpinned
                                .len()
                                .checked_add(table.entries.len())
                                .ok_or(GraphRefusal::Overflow)?;
                            add(&mut self.extra, bytes_for::<Skipped>(skips)?)?;
                            self.max_skips = self
                                .max_skips
                                .checked_add(table.entries.len())
                                .ok_or(GraphRefusal::Overflow)?;
                            let growth = self
                                .growth
                                .get_mut(&source.view)
                                .ok_or(GraphRefusal::Identity)?;
                            growth.targets = growth
                                .targets
                                .checked_add(table.entries.len())
                                .ok_or(GraphRefusal::Overflow)?;
                            growth.pins = growth
                                .pins
                                .checked_add(table.entries.len())
                                .ok_or(GraphRefusal::Overflow)?;
                            self.item = 0;
                            self.stage = 4;
                            Ok(false)
                        } else {
                            self.table = 0;
                            self.item = 0;
                            self.stage = 0;
                            Ok(true)
                        }
                    }
                    4 => {
                        let table = source
                            .tables
                            .get(self.table)
                            .ok_or(GraphRefusal::Identity)?;
                        if let Some(entry) = table.entries.get(self.item) {
                            add(&mut self.bytes, charge_text(&entry.object_path)?)?;
                            add(&mut self.extra, normalization_bound(&entry.object_path)?)?;
                            let strings = text_bytes(entry.name)?
                                .checked_add(text_bytes(&entry.object_path)?)
                                .and_then(|bytes| {
                                    bytes.checked_add(ENTRY_MISSING.len().max(ENTRY_ABI.len()))
                                })
                                .ok_or(GraphRefusal::Overflow)?;
                            add(
                                &mut self.extra,
                                strings.checked_mul(2).ok_or(GraphRefusal::Overflow)?,
                            )?;
                            self.item += 1;
                            Ok(false)
                        } else {
                            self.item = 0;
                            self.stage = 5;
                            Ok(false)
                        }
                    }
                    _ => {
                        let table = source
                            .tables
                            .get(self.table)
                            .ok_or(GraphRefusal::Identity)?;
                        if let Some(skip) = table.unpinned.get(self.item) {
                            add(&mut self.bytes, charge_text(&skip.subject)?)?;
                            add(&mut self.bytes, charge_text(&skip.reason)?)?;
                            self.item += 1;
                            Ok(false)
                        } else {
                            self.table += 1;
                            self.stage = 3;
                            Ok(false)
                        }
                    }
                }
            }

            pub(crate) fn bytes(&self) -> usize {
                self.bytes
            }

            fn extra(&self) -> usize {
                self.extra
            }

            fn max_skips(&self) -> usize {
                self.max_skips
            }

            fn take_growth(&mut self) -> BTreeMap<ProcessViewId, Growth> {
                std::mem::take(&mut self.growth)
            }
        }

        /// Payment for installed canonical modules: moved out of the rebind
        /// cursor by the install sink, held while the canonical owns them.
        #[derive(Debug)]
        pub(crate) struct InstalledModulesBacking {
            input_storage: Option<ResourceLease>,
            output_storage: Option<ResourceLease>,
            header_storage: Option<ResourceLease>,
        }

        /// Owns the original iterator/suffix and every output/temporary request.
        /// No read-only view exists until all original binding and claims finish.
        pub(crate) struct ScannedRebindCursor {
            phase: BindPhase,
            fence: Option<BindFence>,
            cancelled: bool,
            taken: bool,
            completed: bool,
            input_required: Option<usize>,
            extra_required: Option<usize>,
            claim_required: Option<usize>,
            header_bytes: usize,
            input_bytes: usize,
            extra_bytes: usize,
            claim_bytes: usize,
            max_skips: usize,
            growth: BTreeMap<ProcessViewId, Growth>,
            input_measure: ScannedInputMeasure,
            module_pos: usize,
            table_pos: usize,
            item_pos: usize,
            last_view: Option<ProcessViewId>,
            last_pin: Option<PinnedObjectId>,
            bucket: u8,
            originals: Option<std::vec::IntoIter<ScannedModule>>,
            module: Option<ScannedModule>,
            object: Option<PinnedObjectId>,
            entries: Option<std::vec::IntoIter<ScannedEntry>>,
            old_skips: Option<std::vec::IntoIter<Skipped>>,
            old_skip_leaf: Option<Skipped>,
            entry: Option<ScannedEntry>,
            ids: Vec<PinnedObjectId>,
            entry_objects: Vec<Vec<PinnedObjectId>>,
            normalize: Option<Normalize>,
            normalized: Option<String>,
            skip_copy: Option<SkipCopy>,
            skip_primary: Option<Skipped>,
            skip_reason: &'static str,
            modules: Vec<ReconciledModule>,
            skipped: Vec<Skipped>,
            module_drain: Option<ModuleDrain>,
            reconciled_drain: Option<ReconciledDrain>,
            reclaim_stage: u8,
            // Original nested buffers can move into output rows; this payment
            // stays until ALL those owners, not merely the input Vec, die.
            input_storage: Option<ResourceLease>,
            output_storage: Option<ResourceLease>,
            header_storage: Option<ResourceLease>,
        }

        impl ScannedRebindCursor {
            pub(crate) fn new() -> Self {
                Self {
                    phase: BindPhase::New,
                    fence: None,
                    cancelled: false,
                    taken: false,
                    completed: false,
                    input_required: None,
                    extra_required: None,
                    claim_required: None,
                    header_bytes: 0,
                    input_bytes: 0,
                    extra_bytes: 0,
                    claim_bytes: 0,
                    max_skips: 0,
                    growth: BTreeMap::new(),
                    input_measure: ScannedInputMeasure::empty(),
                    module_pos: 0,
                    table_pos: 0,
                    item_pos: 0,
                    last_view: None,
                    last_pin: None,
                    bucket: 0,
                    originals: None,
                    module: None,
                    object: None,
                    entries: None,
                    old_skips: None,
                    old_skip_leaf: None,
                    entry: None,
                    ids: Vec::new(),
                    entry_objects: Vec::new(),
                    normalize: None,
                    normalized: None,
                    skip_copy: None,
                    skip_primary: None,
                    skip_reason: "",
                    modules: Vec::new(),
                    skipped: Vec::new(),
                    module_drain: None,
                    reconciled_drain: None,
                    reclaim_stage: 0,
                    input_storage: None,
                    output_storage: None,
                    header_storage: None,
                }
            }
            pub(crate) fn modules(&self) -> Option<&[ReconciledModule]> {
                (self.phase == BindPhase::Ready).then_some(self.modules.as_slice())
            }
            pub(crate) fn skipped(&self) -> Option<&[Skipped]> {
                (self.phase == BindPhase::Ready).then_some(self.skipped.as_slice())
            }
            pub(crate) fn required_bytes(&self) -> Option<usize> {
                self.extra_required
            }
            pub(crate) fn required_input_bytes(&self) -> Option<usize> {
                self.input_required
            }
            pub(crate) fn required_claim_bytes(&self) -> Option<usize> {
                self.claim_required
            }
            pub(crate) fn cancel(&mut self) {
                self.cancelled = true;
            }

            fn check_pool(&self, reserve: &SemanticResourceReserver) -> Result<(), GraphRefusal> {
                for lease in [
                    &self.header_storage,
                    &self.input_storage,
                    &self.output_storage,
                ] {
                    if lease
                        .as_ref()
                        .is_some_and(|lease| !reserve.covers(lease, 0))
                    {
                        return Err(GraphRefusal::Identity);
                    }
                }
                Ok(())
            }

            fn check_candidate(&self, pins: &PinnedConservativeCursor) -> Result<(), GraphRefusal> {
                let fence = self.fence.ok_or(GraphRefusal::Identity)?;
                let output = pins.output.as_ref().ok_or(GraphRefusal::Identity)?;
                if output.copy_source != Some(fence.candidate) {
                    return Err(GraphRefusal::Identity);
                }
                if output.revision != fence.revision
                    || output.copy_version != fence.version
                    || output.changed.get() != fence.changed
                {
                    return Err(GraphRefusal::SourceChanged);
                }
                if self.taken {
                    if pins.rebind_owner != Some(fence.input) {
                        return Err(GraphRefusal::Identity);
                    }
                } else if pins.phase != Phase::Ready || pins.rebind_owner.is_some() {
                    return Err(GraphRefusal::Identity);
                }
                Ok(())
            }

            fn begin_measure(
                &mut self,
                pins: &PinnedConservativeCursor,
                input: &RetainedScannedInputs,
                reserve: &SemanticResourceReserver,
            ) -> Result<(), GraphRefusal> {
                if pins.phase != Phase::Ready
                    || pins.rebind_owner.is_some()
                    || pins.claim_backing.is_some()
                    || !reserve.covers(&input.storage, 0)
                    || pins
                        .header
                        .as_ref()
                        .is_none_or(|lease| !reserve.covers(lease, 0))
                {
                    return Err(GraphRefusal::Identity);
                }
                let output = pins.output.as_ref().ok_or(GraphRefusal::Identity)?;
                if output.revision == u64::MAX
                    || output
                        .copy_version
                        .checked_add(2)
                        .is_none_or(|version| version == u64::MAX)
                {
                    return Err(GraphRefusal::SourceChanged);
                }
                let header_bytes = std::mem::size_of::<Self>()
                    .checked_add(OWNED_ALLOCATION_PADDING)
                    .and_then(|bytes| {
                        bytes.checked_add(tree::<ProcessViewId, Growth>(input.rows.len()).ok()?)
                    })
                    .ok_or(GraphRefusal::Overflow)?;
                let storage = reserve
                    .reserve(header_bytes)
                    .map_err(GraphRefusal::Storage)?;
                self.fence = Some(BindFence {
                    candidate: output.copy_source.ok_or(GraphRefusal::Identity)?,
                    input: input.identity,
                    revision: output.revision,
                    version: output.copy_version,
                    changed: output.changed.get(),
                });
                self.header_storage = Some(storage);
                self.header_bytes = header_bytes;
                self.input_measure = ScannedInputMeasure::new(input.rows.capacity())?;
                self.extra_bytes = header_bytes
                    .checked_add(bytes_for::<ReconciledModule>(input.rows.len())?)
                    .ok_or(GraphRefusal::Overflow)?;
                self.claim_bytes = tree::<ProcessViewId, ViewClaims>(input.rows.len())?;
                self.phase = BindPhase::MeasureInput;
                Ok(())
            }

            fn measure(
                &mut self,
                pins: &PinnedObjects,
                input: &RetainedScannedInputs,
            ) -> Result<(), GraphRefusal> {
                match self.phase {
                    BindPhase::MeasureInput => {
                        if let Some(module) = input.rows.get(self.module_pos) {
                            if self.input_measure.step(module)? {
                                self.module_pos += 1;
                            }
                        } else {
                            self.input_bytes = self.input_measure.bytes();
                            add(&mut self.extra_bytes, self.input_measure.extra())?;
                            self.max_skips = self.input_measure.max_skips();
                            self.growth = self.input_measure.take_growth();
                            add(&mut self.extra_bytes, bytes_for::<Skipped>(self.max_skips)?)?;
                            self.last_view = None;
                            self.phase = BindPhase::MeasureViews;
                        }
                    }
                    BindPhase::MeasureViews => {
                        if let Some((view, growth)) =
                            next_map(&self.growth, self.last_view.as_ref())
                        {
                            self.last_view = Some(*view);
                            let old = pins.ownership.get(view);
                            let tables = old
                                .map_or(0, |old| old.tables.capacity())
                                .max(growth.tables);
                            let targets = old
                                .map_or(0, |old| old.targets.capacity())
                                .max(growth.targets);
                            let pin_count = old
                                .map_or(0, |old| old.pins.len())
                                .checked_add(growth.pins)
                                .ok_or(GraphRefusal::Overflow)?;
                            let pin_count = old.map_or(0, |old| old.pins.capacity()).max(pin_count);
                            add(&mut self.claim_bytes, bytes_for::<PinnedObjectId>(tables)?)?;
                            add(
                                &mut self.claim_bytes,
                                bytes_for::<(PinnedObjectId, u64)>(targets)?,
                            )?;
                            add(
                                &mut self.claim_bytes,
                                bytes_for::<PinnedObjectId>(pin_count)?,
                            )?;
                        } else {
                            self.last_pin = None;
                            self.phase = BindPhase::MeasurePin;
                        }
                    }
                    BindPhase::MeasurePin => {
                        if let Some((id, entry)) = next_map(&pins.by_id, self.last_pin.as_ref()) {
                            self.last_pin = Some(*id);
                            add(
                                &mut self.extra_bytes,
                                bytes_for::<(String, u64)>(entry.exports.len())?,
                            )?;
                            add(&mut self.extra_bytes, 2 * std::mem::size_of::<usize>())?;
                            self.item_pos = 0;
                            self.phase = BindPhase::MeasurePinExports;
                        } else {
                            self.input_required = Some(self.input_bytes);
                            self.claim_required = Some(self.claim_bytes);
                            self.extra_required = Some(
                                self.extra_bytes
                                    .checked_add(self.claim_bytes)
                                    .ok_or(GraphRefusal::Overflow)?,
                            );
                            self.phase = BindPhase::Admit;
                        }
                    }
                    BindPhase::MeasurePinExports => {
                        let entry = pins
                            .by_id
                            .get(&self.last_pin.ok_or(GraphRefusal::Identity)?)
                            .ok_or(GraphRefusal::Identity)?;
                        if let Some((text, _)) = entry.exports.get(self.item_pos) {
                            add(&mut self.extra_bytes, charge_text(text)?)?;
                            self.item_pos += 1;
                        } else {
                            self.phase = BindPhase::MeasurePin;
                        }
                    }
                    _ => return Err(GraphRefusal::Identity),
                }
                Ok(())
            }
        }

        impl ScannedRebindCursor {
            fn admit(
                &mut self,
                pins: &mut PinnedConservativeCursor,
                input: &mut Option<RetainedScannedInputs>,
                reserve: &SemanticResourceReserver,
            ) -> Result<(), GraphRefusal> {
                let original = input.as_ref().ok_or(GraphRefusal::Identity)?;
                if !reserve.covers(
                    &original.storage,
                    self.input_required.ok_or(GraphRefusal::Identity)?,
                ) {
                    return Err(GraphRefusal::Identity);
                }
                let output_bytes = self
                    .extra_bytes
                    .checked_sub(self.header_bytes)
                    .ok_or(GraphRefusal::Overflow)?;
                // Both reservations are local until ALL precharges succeed.
                // A second refusal refunds no live input/claim allocation.
                let output = reserve
                    .reserve(output_bytes)
                    .map_err(GraphRefusal::Storage)?;
                let claims = reserve
                    .reserve(self.claim_required.ok_or(GraphRefusal::Identity)?)
                    .map_err(GraphRefusal::Storage)?;
                let updated = self
                    .fence
                    .ok_or(GraphRefusal::Identity)?
                    .version
                    .checked_add(2)
                    .filter(|version| *version < u64::MAX)
                    .ok_or(GraphRefusal::SourceChanged)?;
                let original = input.take().ok_or(GraphRefusal::Identity)?;
                let capacity = original.rows.len();
                let identity = original.identity;
                self.originals = Some(original.rows.into_iter());
                self.input_storage = Some(original.storage);
                self.output_storage = Some(output);
                // The candidate, not this module cursor, owns payment for ALL
                // appended/reset-derived claim backing before the first write.
                pins.claim_backing = Some(claims);
                pins.rebind_owner = Some(identity);
                pins.rebind_complete = false;
                pins.phase = Phase::Rebinding;
                pins.output
                    .as_mut()
                    .ok_or(GraphRefusal::Identity)?
                    .copy_version = updated;
                self.fence.as_mut().ok_or(GraphRefusal::Identity)?.version = updated;
                self.taken = true;
                self.modules = Vec::with_capacity(capacity);
                self.skipped = Vec::with_capacity(self.max_skips);
                self.last_view = None;
                self.phase = BindPhase::Reset;
                Ok(())
            }

            fn reset_one(&mut self, pins: &mut PinnedObjects) {
                if let Some((view, _)) = next_map(&pins.ownership, self.last_view.as_ref()) {
                    let view = *view;
                    if let Some(claims) = pins.ownership.get_mut(&view) {
                        // Both element types are Copy/no-drop. Capacity stays
                        // owned/paid; one original ownership row per credit.
                        claims.tables.clear();
                        claims.targets.clear();
                    }
                    self.last_view = Some(view);
                } else {
                    self.last_view = None;
                    self.bucket = 0;
                    self.phase = BindPhase::Grow;
                }
            }

            fn grow_one(
                &mut self,
                pins: &mut PinnedObjects,
                old_prefix: &mut Option<(ProcessViewId, std::vec::IntoIter<PinnedObjectId>)>,
            ) -> Result<(), GraphRefusal> {
                if let Some((view, original)) = old_prefix.as_mut() {
                    let view = *view;
                    if let Some(id) = original.next() {
                        pins.ownership
                            .get_mut(&view)
                            .ok_or(GraphRefusal::Identity)?
                            .pins
                            .push(id);
                    } else {
                        // Empty iterator: only its original scalar backing dies.
                        // It stayed H1-owned and base-paid throughout transfer.
                        drop(old_prefix.take());
                        self.last_view = Some(view);
                        self.bucket = 0;
                    }
                    return Ok(());
                }
                let Some((view, growth)) = next_map(&self.growth, self.last_view.as_ref()) else {
                    self.phase = BindPhase::NextModule;
                    return Ok(());
                };
                let view = *view;
                if let Some(old) = pins.ownership.get_mut(&view) {
                    match self.bucket {
                        // These vectors were cleared one row at a time first;
                        // they carry no populated prefix into reserve_exact.
                        0 if old.tables.capacity() < growth.tables => {
                            old.tables.reserve_exact(growth.tables)
                        }
                        1 if old.targets.capacity() < growth.targets => {
                            old.targets.reserve_exact(growth.targets)
                        }
                        2 => {
                            let wanted = old
                                .pins
                                .len()
                                .checked_add(growth.pins)
                                .ok_or(GraphRefusal::Overflow)?;
                            if old.pins.capacity() < wanted {
                                let fresh = Vec::with_capacity(wanted);
                                let original = std::mem::replace(&mut old.pins, fresh);
                                *old_prefix = Some((view, original.into_iter()));
                                return Ok(());
                            }
                        }
                        _ => {}
                    }
                }
                if self.bucket == 2 {
                    self.last_view = Some(view);
                    self.bucket = 0;
                } else {
                    self.bucket += 1;
                }
                Ok(())
            }

            fn resolve_normalized(
                &mut self,
                pins: &PinnedObjects,
                key: ObjectKey,
            ) -> Result<Option<PinnedObjectId>, GraphRefusal> {
                let Some(path) = self.normalized.take() else {
                    return Ok(None);
                };
                let namespace = self
                    .module
                    .as_ref()
                    .ok_or(GraphRefusal::Identity)?
                    .mount_namespace;
                let raw = RawObjectInstance {
                    mount_namespace: Some(namespace),
                    key,
                    path,
                };
                Ok(pins.raw_to_id.get(&raw).copied())
            }

            fn bind_one(
                &mut self,
                pins: &mut PinnedObjects,
                old_pin_prefix: &mut Option<(ProcessViewId, std::vec::IntoIter<PinnedObjectId>)>,
            ) -> Result<(), GraphRefusal> {
                match self.phase {
                    BindPhase::Reset => self.reset_one(pins),
                    BindPhase::Grow => self.grow_one(pins, old_pin_prefix)?,
                    BindPhase::NextModule => {
                        if let Some(module) = self
                            .originals
                            .as_mut()
                            .ok_or(GraphRefusal::Identity)?
                            .next()
                        {
                            self.module = Some(module);
                            self.object = None;
                            self.table_pos = 0;
                            self.item_pos = 0;
                            self.phase = BindPhase::ProviderStart;
                        } else {
                            self.completed = true;
                            self.phase = BindPhase::Ready;
                        }
                    }
                    BindPhase::ProviderStart => {
                        let original = &self.module.as_ref().ok_or(GraphRefusal::Identity)?.path;
                        self.normalize = Normalize::new(original);
                        if self.normalize.is_some() {
                            self.phase = BindPhase::ProviderNormalize;
                        } else {
                            self.skip_reason = MODULE_MISSING;
                            self.phase = BindPhase::ModuleSkip;
                        }
                    }
                    BindPhase::ProviderNormalize | BindPhase::EntryNormalize => {
                        let provider = self.phase == BindPhase::ProviderNormalize;
                        let original = if provider {
                            self.module.as_ref().map(|module| module.path.as_str())
                        } else {
                            self.entry.as_ref().map(|entry| entry.object_path.as_str())
                        }
                        .ok_or(GraphRefusal::Identity)?;
                        if self
                            .normalize
                            .as_mut()
                            .ok_or(GraphRefusal::Identity)?
                            .advance(original)
                        {
                            let mut normalized =
                                self.normalize.take().ok_or(GraphRefusal::Identity)?;
                            self.normalized = Some(std::mem::take(&mut normalized.path));
                            // Only its primitive stack backing remains here.
                            drop(normalized);
                            self.phase = if provider {
                                BindPhase::ProviderResolve
                            } else {
                                BindPhase::EntryResolve
                            };
                        }
                    }
                    BindPhase::ProviderResolve => {
                        let key = self.module.as_ref().ok_or(GraphRefusal::Identity)?.key;
                        match self.resolve_normalized(pins, key)? {
                            None => {
                                self.skip_reason = MODULE_MISSING;
                                self.phase = BindPhase::ModuleSkip;
                            }
                            Some(object) => {
                                let old =
                                    pins.by_id.get(&object).ok_or(GraphRefusal::SourceChanged)?;
                                let module = self.module.as_ref().ok_or(GraphRefusal::Identity)?;
                                if module.decoder_abi.is_some_and(|decoded| decoded != old.abi) {
                                    self.skip_reason = MODULE_ABI;
                                    self.phase = BindPhase::ModuleSkip;
                                } else {
                                    self.object = Some(object);
                                    self.entry_objects = Vec::with_capacity(module.tables.len());
                                    self.table_pos = 0;
                                    self.phase = BindPhase::TableStart;
                                }
                            }
                        }
                    }
                    BindPhase::ModuleSkip => {
                        if self.skip_copy.is_none() {
                            self.skip_copy = Some(SkipCopy::new());
                        } else {
                            let subject = &self.module.as_ref().ok_or(GraphRefusal::Identity)?.path;
                            if self
                                .skip_copy
                                .as_mut()
                                .ok_or(GraphRefusal::Identity)?
                                .advance(subject, "", self.skip_reason)
                            {
                                let skip =
                                    self.skip_copy.take().ok_or(GraphRefusal::Identity)?.skip;
                                self.skipped.push(skip);
                                let module = self.module.take().ok_or(GraphRefusal::Identity)?;
                                self.module_drain = Some(ModuleDrain::new(module));
                                self.phase = BindPhase::DiscardModule;
                            }
                        }
                    }
                    BindPhase::DiscardModule => {
                        if self
                            .module_drain
                            .as_mut()
                            .ok_or(GraphRefusal::Identity)?
                            .advance()
                        {
                            self.module_drain = None;
                            self.phase = BindPhase::NextModule;
                        }
                    }
                    BindPhase::TableStart => {
                        let module = self.module.as_mut().ok_or(GraphRefusal::Identity)?;
                        if let Some(table) = module.tables.get_mut(self.table_pos) {
                            let count = table.entries.len();
                            self.entries = Some(std::mem::take(&mut table.entries).into_iter());
                            table.entries = Vec::with_capacity(count);
                            self.ids = Vec::with_capacity(count);
                            let wanted = table
                                .unpinned
                                .len()
                                .checked_add(count)
                                .ok_or(GraphRefusal::Overflow)?;
                            if table.unpinned.capacity() < wanted {
                                let fresh = Vec::with_capacity(wanted);
                                let original = std::mem::replace(&mut table.unpinned, fresh);
                                self.old_skips = Some(original.into_iter());
                                self.phase = BindPhase::MoveSkips;
                            } else {
                                self.phase = BindPhase::NextEntry;
                            }
                        } else {
                            self.table_pos = 0;
                            self.phase = BindPhase::ClaimTables;
                        }
                    }
                    BindPhase::MoveSkips => {
                        let original = self.old_skips.as_mut().ok_or(GraphRefusal::Identity)?;
                        if let Some(skip) = original.next() {
                            self.module
                                .as_mut()
                                .and_then(|module| module.tables.get_mut(self.table_pos))
                                .ok_or(GraphRefusal::Identity)?
                                .unpinned
                                .push(skip);
                        } else {
                            // Every original record has moved; dropping this
                            // empty iterator frees only the old Vec allocation.
                            drop(self.old_skips.take());
                            self.phase = BindPhase::NextEntry;
                        }
                    }
                    BindPhase::NextEntry => {
                        if let Some(entry) =
                            self.entries.as_mut().ok_or(GraphRefusal::Identity)?.next()
                        {
                            self.normalize = Normalize::new(&entry.object_path);
                            self.entry = Some(entry);
                            self.phase = if self.normalize.is_some() {
                                BindPhase::EntryNormalize
                            } else {
                                BindPhase::EntryResolve
                            };
                        } else {
                            self.phase = BindPhase::FinishTable;
                        }
                    }
                    BindPhase::EntryResolve => {
                        let key = self.entry.as_ref().ok_or(GraphRefusal::Identity)?.object;
                        let candidate = self.resolve_normalized(pins, key)?;
                        let provider = self.object.ok_or(GraphRefusal::Identity)?;
                        let compatible = candidate.is_some_and(|target| {
                            matches!((pins.abi_for(target), pins.abi_for(provider)),
                                (Some(target), Some(provider)) if target == provider)
                        });
                        if compatible {
                            let id = candidate.ok_or(GraphRefusal::Identity)?;
                            self.ids.push(id);
                            let entry = self.entry.take().ok_or(GraphRefusal::Identity)?;
                            self.module
                                .as_mut()
                                .and_then(|module| module.tables.get_mut(self.table_pos))
                                .ok_or(GraphRefusal::Identity)?
                                .entries
                                .push(entry);
                            self.phase = BindPhase::NextEntry;
                        } else {
                            self.skip_reason = if candidate.is_some() {
                                ENTRY_ABI
                            } else {
                                ENTRY_MISSING
                            };
                            self.phase = BindPhase::EntrySkip;
                        }
                    }
                    BindPhase::EntrySkip => {
                        if self.skip_copy.is_none() {
                            self.skip_copy = Some(SkipCopy::new());
                        } else {
                            let entry = self.entry.as_ref().ok_or(GraphRefusal::Identity)?;
                            if self
                                .skip_copy
                                .as_mut()
                                .ok_or(GraphRefusal::Identity)?
                                .advance(entry.name, &entry.object_path, self.skip_reason)
                            {
                                self.skip_primary =
                                    Some(self.skip_copy.take().ok_or(GraphRefusal::Identity)?.skip);
                                self.phase = BindPhase::EntrySkipCopy;
                            }
                        }
                    }
                    BindPhase::EntrySkipCopy => {
                        if self.skip_copy.is_none() {
                            self.skip_copy = Some(SkipCopy::new());
                        } else {
                            let skip = self.skip_primary.as_ref().ok_or(GraphRefusal::Identity)?;
                            if self
                                .skip_copy
                                .as_mut()
                                .ok_or(GraphRefusal::Identity)?
                                .advance(&skip.subject, &skip.reason, "")
                            {
                                let copy =
                                    self.skip_copy.take().ok_or(GraphRefusal::Identity)?.skip;
                                let primary =
                                    self.skip_primary.take().ok_or(GraphRefusal::Identity)?;
                                self.module
                                    .as_mut()
                                    .and_then(|module| module.tables.get_mut(self.table_pos))
                                    .ok_or(GraphRefusal::Identity)?
                                    .unpinned
                                    .push(primary);
                                self.skipped.push(copy);
                                self.phase = BindPhase::DropEntry;
                            }
                        }
                    }
                    BindPhase::DropEntry => {
                        drop(self.entry.take());
                        self.phase = BindPhase::NextEntry;
                    }
                    BindPhase::FinishTable => {
                        if self
                            .entries
                            .as_ref()
                            .is_some_and(|entries| !entries.as_slice().is_empty())
                        {
                            return Err(GraphRefusal::Identity);
                        }
                        drop(self.entries.take());
                        self.entry_objects.push(std::mem::take(&mut self.ids));
                        self.table_pos += 1;
                        self.phase = BindPhase::TableStart;
                    }
                    BindPhase::ClaimTables => {
                        let module = self.module.as_ref().ok_or(GraphRefusal::Identity)?;
                        let growth = self
                            .growth
                            .get(&module.view)
                            .ok_or(GraphRefusal::Identity)?;
                        match pins.ownership.entry(module.view) {
                            std::collections::btree_map::Entry::Vacant(slot) => {
                                slot.insert(ViewClaims {
                                    tables: Vec::with_capacity(growth.tables),
                                    targets: Vec::with_capacity(growth.targets),
                                    pins: Vec::with_capacity(growth.pins),
                                });
                            }
                            std::collections::btree_map::Entry::Occupied(mut slot)
                                if self.table_pos < module.tables.len() =>
                            {
                                slot.get_mut()
                                    .tables
                                    .push(self.object.ok_or(GraphRefusal::Identity)?);
                                self.table_pos += 1;
                            }
                            std::collections::btree_map::Entry::Occupied(_) => {
                                self.phase = BindPhase::ClaimModule;
                            }
                        }
                    }
                    BindPhase::ClaimModule => {
                        let view = self.module.as_ref().ok_or(GraphRefusal::Identity)?.view;
                        pins.ownership
                            .get_mut(&view)
                            .ok_or(GraphRefusal::Identity)?
                            .pins
                            .push(self.object.ok_or(GraphRefusal::Identity)?);
                        self.table_pos = 0;
                        self.item_pos = 0;
                        self.phase = BindPhase::ClaimEntries;
                    }
                    BindPhase::ClaimEntries => {
                        let module = self.module.as_ref().ok_or(GraphRefusal::Identity)?;
                        if let Some(table) = module.tables.get(self.table_pos) {
                            if let Some(entry) = table.entries.get(self.item_pos) {
                                let id = *self
                                    .entry_objects
                                    .get(self.table_pos)
                                    .and_then(|ids| ids.get(self.item_pos))
                                    .ok_or(GraphRefusal::Identity)?;
                                let claims = pins
                                    .ownership
                                    .get_mut(&module.view)
                                    .ok_or(GraphRefusal::Identity)?;
                                claims.targets.push((id, entry.file_offset));
                                claims.pins.push(id);
                                self.item_pos += 1;
                            } else {
                                self.table_pos += 1;
                                self.item_pos = 0;
                            }
                        } else {
                            self.phase = BindPhase::FinishModule;
                        }
                    }
                    BindPhase::FinishModule => {
                        let object = self.object.take().ok_or(GraphRefusal::Identity)?;
                        let exports = pins
                            .by_id
                            .get(&object)
                            .ok_or(GraphRefusal::SourceChanged)?
                            .exports
                            .clone();
                        self.modules.push(ReconciledModule {
                            scanned: self.module.take().ok_or(GraphRefusal::Identity)?,
                            object,
                            entry_objects: std::mem::take(&mut self.entry_objects),
                            exports,
                        });
                        self.phase = BindPhase::NextModule;
                    }
                    _ => return Err(GraphRefusal::Identity),
                }
                Ok(())
            }
        }

        impl PinnedConservativeCursor {
            pub(crate) fn poll_scanned_rebind(
                &mut self,
                input: &mut Option<RetainedScannedInputs>,
                cursor: &mut ScannedRebindCursor,
                reserve: &SemanticResourceReserver,
                work: usize,
            ) -> Result<GraphStep, GraphRefusal> {
                if work == 0 {
                    return Ok(GraphStep::Yielded);
                }
                if cursor.cancelled {
                    return Err(GraphRefusal::Cancelled);
                }
                cursor.check_pool(reserve)?;
                let mut credits = work;
                if cursor.phase == BindPhase::New {
                    cursor.begin_measure(
                        self,
                        input.as_ref().ok_or(GraphRefusal::Identity)?,
                        reserve,
                    )?;
                    // Construction/binding of the first measurement itself
                    // consumes one credit and takes no original allocation.
                    credits -= 1;
                }
                cursor.check_candidate(self)?;
                if cursor.taken {
                    if input.is_some() {
                        return Err(GraphRefusal::Identity);
                    }
                } else {
                    let original = input.as_ref().ok_or(GraphRefusal::Identity)?;
                    if Some(original.identity) != cursor.fence.map(|fence| fence.input)
                        || !reserve.covers(&original.storage, 0)
                    {
                        return Err(GraphRefusal::Identity);
                    }
                }
                if matches!(cursor.phase, BindPhase::Reclaim | BindPhase::Reclaimed) {
                    return Err(GraphRefusal::Cancelled);
                }
                for _ in 0..credits {
                    match cursor.phase {
                        BindPhase::MeasureInput
                        | BindPhase::MeasureViews
                        | BindPhase::MeasurePin
                        | BindPhase::MeasurePinExports => {
                            let original = input.as_ref().ok_or(GraphRefusal::Identity)?;
                            cursor.measure(
                                self.output.as_ref().ok_or(GraphRefusal::Identity)?,
                                original,
                            )?;
                        }
                        BindPhase::Admit => cursor.admit(self, input, reserve)?,
                        BindPhase::Ready => return Ok(GraphStep::Ready),
                        _ => {
                            cursor.bind_one(
                                self.output.as_mut().ok_or(GraphRefusal::Identity)?,
                                &mut self.rebind_old_pins,
                            )?;
                            if cursor.phase == BindPhase::Ready {
                                self.rebind_complete = true;
                                return Ok(GraphStep::Ready);
                            }
                        }
                    }
                }
                Ok(GraphStep::Advanced)
            }

            #[cfg(test)]
            pub(crate) fn reference_rebind_claims_for_test(
                &self,
                view: ProcessViewId,
            ) -> Option<&ViewClaims> {
                self.output.as_ref()?.ownership.get(&view)
            }
        }

        impl ScannedRebindCursor {
            /// Reclamation, not graph/semantic completion. With no borrowed pin
            /// owner, unknown shared or Weak export backing remains paid/refused.
            pub(crate) fn reclaim(
                &mut self,
                mut pins: Option<&mut PinnedConservativeCursor>,
                reserve: &SemanticResourceReserver,
                work: usize,
            ) -> Result<GraphStep, GraphRefusal> {
                if work == 0 {
                    return Ok(GraphStep::Yielded);
                }
                self.check_pool(reserve)?;
                if self.taken && !self.completed && pins.is_none() {
                    return Err(GraphRefusal::Identity);
                }
                if let Some(owner) = pins.as_deref()
                    && self.fence.is_some()
                {
                    if self.phase == BindPhase::Reclaimed {
                        let fence = self.fence.ok_or(GraphRefusal::Identity)?;
                        if owner.output.as_ref().and_then(|output| output.copy_source)
                            != Some(fence.candidate)
                            || owner.rebind_owner.is_some_and(|held| held != fence.input)
                        {
                            return Err(GraphRefusal::Identity);
                        }
                    } else {
                        self.check_candidate(owner)?;
                    }
                }
                if self.phase == BindPhase::Reclaimed {
                    self.release_loan(pins)?;
                    return Ok(GraphStep::Ready);
                }
                self.phase = BindPhase::Reclaim;
                for _ in 0..work {
                    if let Some(owner) = pins.as_deref_mut()
                        && let Some((_, original)) = owner.rebind_old_pins.as_mut()
                    {
                        if original.next().is_none() {
                            drop(owner.rebind_old_pins.take());
                        }
                        // Abort disposes at most one original scalar claim;
                        // both old/new buffers remain with their paid H1 owner.
                        continue;
                    }
                    let actual = pins.as_deref().and_then(|owner| owner.output.as_ref());
                    self.reclaim_one(actual, None, false)?;
                    if self.phase == BindPhase::Reclaimed {
                        self.release_loan(pins)?;
                        return Ok(GraphStep::Ready);
                    }
                }
                Ok(GraphStep::Advanced)
            }

            /// O(1) install sink: swaps the bound modules into the canonical;
            /// the cursor now holds the old canonical modules for
            /// `reclaim_installed`. The module payment moves into the backing.
            pub(crate) fn install_ready(
                &mut self,
                canonical: &mut Vec<ReconciledModule>,
            ) -> Result<InstalledModulesBacking, GraphRefusal> {
                if self.cancelled {
                    return Err(GraphRefusal::Cancelled);
                }
                match self.phase {
                    BindPhase::Ready => {}
                    BindPhase::Installed | BindPhase::Reclaim | BindPhase::Reclaimed => {
                        return Err(GraphRefusal::Cancelled);
                    }
                    _ => return Err(GraphRefusal::Identity),
                }
                std::mem::swap(&mut self.modules, canonical);
                self.phase = BindPhase::Installed;
                Ok(InstalledModulesBacking {
                    input_storage: self.input_storage.take(),
                    output_storage: self.output_storage.take(),
                    header_storage: self.header_storage.take(),
                })
            }

            /// Reclaims the old canonical modules against the live installed
            /// pins: aliased exports are released, Session-shared exports drop
            /// our clone, exclusive slices drain element-wise, and the pins
            /// loan is released last.
            pub(crate) fn reclaim_installed(
                &mut self,
                pins: &mut PinnedConservativeCursor,
                live_pins: &PinnedObjects,
                handoff: &mut RetiredFileHandoff,
                reserve: &SemanticResourceReserver,
                work: usize,
            ) -> Result<GraphStep, GraphRefusal> {
                // Module exports drain exclusively and modules hold no files,
                // so installed rebind reclaim takes but never fills the
                // handoff; the shared reservation stays untouched. These
                // parameters keep the graph's per-credit reclaim loop uniform.
                let _ = (handoff, reserve);
                if work == 0 {
                    return Ok(GraphStep::Yielded);
                }
                if self.phase == BindPhase::Reclaimed {
                    return Ok(GraphStep::Ready);
                }
                if self.phase != BindPhase::Installed {
                    return Err(GraphRefusal::Identity);
                }
                let fence = self.fence.ok_or(GraphRefusal::Identity)?;
                if live_pins.copy_source != Some(fence.candidate)
                    || pins.installed != Some(fence.candidate)
                    || pins.rebind_owner.is_some_and(|held| held != fence.input)
                    || pins.rebind_old_pins.is_some()
                {
                    return Err(GraphRefusal::Identity);
                }
                for _ in 0..work {
                    let old = pins.output.as_ref();
                    self.reclaim_one(Some(live_pins), old, true)?;
                    if self.phase == BindPhase::Reclaimed {
                        pins.rebind_owner = None;
                        return Ok(GraphStep::Ready);
                    }
                }
                Ok(GraphStep::Advanced)
            }

            fn release_loan(
                &self,
                pins: Option<&mut PinnedConservativeCursor>,
            ) -> Result<(), GraphRefusal> {
                if self.taken
                    && let Some(pins) = pins
                {
                    let fence = self.fence.ok_or(GraphRefusal::Identity)?;
                    if pins.rebind_old_pins.is_some() {
                        return Err(GraphRefusal::Identity);
                    }
                    if let Some(owner) = pins.rebind_owner {
                        if owner != fence.input {
                            return Err(GraphRefusal::Identity);
                        }
                        pins.rebind_owner = None;
                        pins.rebind_complete = false;
                        pins.phase = if self.completed && !self.cancelled {
                            Phase::Ready
                        } else {
                            Phase::RebindAborted
                        };
                    }
                }
                Ok(())
            }

            fn reclaim_one(
                &mut self,
                pins: Option<&PinnedObjects>,
                old: Option<&PinnedObjects>,
                installed: bool,
            ) -> Result<(), GraphRefusal> {
                if let Some(skip) = &mut self.old_skip_leaf {
                    if reclaim_skip(skip) {
                        self.old_skip_leaf = None;
                    }
                    return Ok(());
                }
                if let Some(original) = &mut self.old_skips {
                    if let Some(skip) = original.next() {
                        self.old_skip_leaf = Some(skip);
                    } else {
                        drop(self.old_skips.take());
                    }
                    return Ok(());
                }
                if let Some(module) = &mut self.reconciled_drain {
                    if module.advance(pins, old, installed)? {
                        self.reconciled_drain = None;
                    }
                    return Ok(());
                }
                if let Some(module) = &mut self.module_drain {
                    if module.advance() {
                        self.module_drain = None;
                    }
                    return Ok(());
                }
                match self.reclaim_stage {
                    0 => {
                        if let Some(normalize) = &mut self.normalize {
                            if normalize.reclaim_one() {
                                self.normalize = None;
                            }
                        } else {
                            self.reclaim_stage = 1;
                        }
                    }
                    1 => {
                        drop(self.normalized.take());
                        self.reclaim_stage = 2;
                    }
                    2 => {
                        if let Some(copy) = &mut self.skip_copy {
                            if reclaim_skip(&mut copy.skip) {
                                self.skip_copy = None;
                            }
                        } else {
                            self.reclaim_stage = 3;
                        }
                    }
                    3 => {
                        if let Some(skip) = &mut self.skip_primary {
                            if reclaim_skip(skip) {
                                self.skip_primary = None;
                            }
                        } else {
                            self.reclaim_stage = 4;
                        }
                    }
                    4 => {
                        drop(self.entry.take());
                        self.reclaim_stage = 5;
                    }
                    5 => {
                        if let Some(entries) = &mut self.entries {
                            if let Some(entry) = entries.next() {
                                drop(entry.object_path);
                            } else {
                                drop(self.entries.take());
                            }
                        } else {
                            self.reclaim_stage = 6;
                        }
                    }
                    6 => {
                        drop(std::mem::take(&mut self.ids));
                        self.reclaim_stage = 7;
                    }
                    7 => {
                        if self.entry_objects.pop().is_none() {
                            drop(std::mem::take(&mut self.entry_objects));
                            self.reclaim_stage = 8;
                        }
                    }
                    8 => {
                        if let Some(module) = self.module.take() {
                            self.module_drain = Some(ModuleDrain::new(module));
                        } else {
                            self.reclaim_stage = 9;
                        }
                    }
                    9 => {
                        if let Some(originals) = &mut self.originals {
                            if let Some(module) = originals.next() {
                                self.module_drain = Some(ModuleDrain::new(module));
                            } else {
                                drop(self.originals.take());
                            }
                        } else {
                            self.reclaim_stage = 10;
                        }
                    }
                    10 => {
                        if let Some(module) = self.modules.pop() {
                            self.reconciled_drain = Some(ReconciledDrain::new(module));
                        } else {
                            drop(std::mem::take(&mut self.modules));
                            self.reclaim_stage = 11;
                        }
                    }
                    11 => {
                        if let Some(skip) = &mut self.skip_primary {
                            if reclaim_skip(skip) {
                                self.skip_primary = None;
                            }
                        } else if let Some(skip) = self.skipped.pop() {
                            self.skip_primary = Some(skip);
                        } else {
                            drop(std::mem::take(&mut self.skipped));
                            self.reclaim_stage = 12;
                        }
                    }
                    12 => {
                        if self.growth.pop_first().is_none() {
                            drop(std::mem::take(&mut self.growth));
                            self.reclaim_stage = 13;
                        }
                    }
                    // Refunds follow actual nested/suffix/empty-root teardown.
                    13 => {
                        self.input_storage = None;
                        self.reclaim_stage = 14;
                    }
                    14 => {
                        self.output_storage = None;
                        self.reclaim_stage = 15;
                    }
                    15 => {
                        self.header_storage = None;
                        self.reclaim_stage = 16;
                    }
                    _ => {
                        self.phase = BindPhase::Reclaimed;
                    }
                }
                Ok(())
            }

            #[cfg(test)]
            pub(crate) fn reference_current_unpinned_for_test(
                &self,
            ) -> Option<(usize, &[Skipped])> {
                let table = self.module.as_ref()?.tables.get(self.table_pos)?;
                Some((table.unpinned.capacity(), table.unpinned.as_slice()))
            }

            #[cfg(test)]
            pub(crate) fn reference_pending_exports_for_test(
                &self,
                object: PinnedObjectId,
            ) -> Option<&[(String, u64)]> {
                if let Some(module) = &self.reconciled_drain
                    && module.object == object
                {
                    return module.exports.as_deref();
                }
                self.modules
                    .iter()
                    .find(|module| module.object == object)
                    .map(|module| module.exports.as_ref())
            }
        }

        struct ReconciledDrain {
            object: PinnedObjectId,
            module: Option<ModuleDrain>,
            ids: Vec<Vec<PinnedObjectId>>,
            exports: Option<Arc<[(String, u64)]>>,
            drained: usize,
        }
        impl ReconciledDrain {
            fn new(module: ReconciledModule) -> Self {
                Self {
                    object: module.object,
                    module: Some(ModuleDrain::new(module.scanned)),
                    ids: module.entry_objects,
                    exports: Some(module.exports),
                    drained: 0,
                }
            }
            fn advance(
                &mut self,
                pins: Option<&PinnedObjects>,
                old: Option<&PinnedObjects>,
                installed: bool,
            ) -> Result<bool, GraphRefusal> {
                if let Some(module) = &mut self.module {
                    if module.advance() {
                        self.module = None;
                    }
                    return Ok(false);
                }
                if self.ids.pop().is_some() {
                    return Ok(false);
                }
                if self.ids.capacity() != 0 {
                    drop(std::mem::take(&mut self.ids));
                    return Ok(false);
                }
                if let Some(exports) = self.exports.as_mut() {
                    let live_alias = pins
                        .and_then(|pins| pins.by_id.get(&self.object))
                        .is_some_and(|entry| Arc::ptr_eq(&entry.exports, exports));
                    let old_alias = old
                        .and_then(|pins| pins.by_id.get(&self.object))
                        .is_some_and(|entry| Arc::ptr_eq(&entry.exports, exports));
                    if live_alias || old_alias {
                        drop(self.exports.take());
                        return Ok(false);
                    }
                    if installed && Arc::strong_count(exports) > 1 {
                        // Installed mode only: a Session-held clone proves our
                        // drop cannot be the last one. Release our share as
                        // one leaf instead of forgetting the graph.
                        drop(self.exports.take());
                        return Ok(false);
                    }
                    let slice = Arc::get_mut(exports).ok_or(GraphRefusal::Identity)?;
                    if self.drained < slice.len() {
                        drop(std::mem::take(&mut slice[self.drained].0));
                        self.drained += 1;
                        return Ok(false);
                    }
                    // The same approved final-layout transition as H1. No
                    // mutable/public Arc exposure exists in reclamation.
                    let slice = Arc::get_mut(exports).ok_or(GraphRefusal::Identity)?;
                    if slice.len() != self.drained {
                        return Err(GraphRefusal::Identity);
                    }
                    let exports = self.exports.take().ok_or(GraphRefusal::Identity)?;
                    // SAFETY: each owned String was taken/freed individually;
                    // get_mut just re-proved exclusivity/noWeak, drained==len,
                    // and the original allocation/metadata is transferred once.
                    unsafe {
                        deallocate_drained_unique_arc(exports);
                    }
                    return Ok(false);
                }
                Ok(true)
            }
        }
    }

    #[cfg(test)]
    mod lifecycle_tests {
        use super::*;

        #[test]
        fn file_share_release_requires_actual_live_alias() {
            let (_dir, source, _) = super::super::tests::conservative_cursor_fixture();
            let (id, original) = source.by_id.first_key_value().unwrap();
            let id = *id;
            let actual_fd = original.file.as_raw_fd();
            let mut independent = source.clone();
            let reopened = std::fs::File::open(&original.path).unwrap();
            assert_ne!(reopened.as_raw_fd(), actual_fd);
            assert_eq!(pin_of(&reopened).unwrap(), original.pin);
            independent.by_id.get_mut(&id).unwrap().file = Arc::new(reopened);
            let mut wrong = source.clone();
            let different = source
                .by_id
                .range((Excluded(id), Unbounded))
                .next()
                .unwrap()
                .1;
            wrong.by_id.get_mut(&id).unwrap().file = different.file.clone();
            let mut entry = EntryReclaim::new(id, original.clone());
            for _ in 0..4 {
                assert!(!entry.advance(None).unwrap());
            }
            assert_eq!(
                entry.field, 4,
                "actual leaf progress reached the file share"
            );
            for borrowed in [None, Some(&independent), Some(&wrong)] {
                assert!(matches!(
                    entry.advance(borrowed),
                    Err(GraphRefusal::Identity)
                ));
                assert_eq!(entry.field, 4);
                assert!(
                    entry
                        .file
                        .as_ref()
                        .is_some_and(|file| file.as_raw_fd() == actual_fd)
                );
                // SAFETY: F_GETFD observes this actual owned descriptor only.
                assert!(unsafe { libc::fcntl(actual_fd, libc::F_GETFD) } >= 0);
            }
            assert!(!entry.advance(Some(&source)).unwrap());
            assert_eq!(entry.field, 5);
            assert!(entry.file.is_none());
            // The borrowed SAME Arc remains live after releasing our share.
            assert!(unsafe { libc::fcntl(actual_fd, libc::F_GETFD) } >= 0);
        }
    }
}

const AMBIGUOUS_SUBJECT: &str = "discovery subject";
const AMBIGUOUS_REASON: &str = "physical identity is ambiguous: equal mapping keys had unequal or unavailable full opened-file identities; the collision group was not attached";

fn ambiguous_identity_skip() -> Skipped {
    Skipped {
        subject: AMBIGUOUS_SUBJECT.into(),
        reason: AMBIGUOUS_REASON.into(),
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
        let entry = match Entry::new(
            file,
            pin,
            object.path.clone(),
            &inspected,
            raw,
            mapping,
            None,
        ) {
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
    pin_scanned_view_objects_with(view, modules, budget, &self_mapped_file)
}

/// Reads a pinned fd's `vm_file` identity ([`self_mapped_file`]).
type ReadPinnedIdentity<'a> = &'a dyn Fn(&std::fs::File) -> Result<MappedFile, String>;

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
            scanned,
            pinned_identity,
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
    pinned.bump_copy_version();
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
    scanned: Option<FileIdentity>,
    pinned_identity: ReadPinnedIdentity<'_>,
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
    let before = pin_of(&file)?;
    let mapped = budget
        .retained_mapped_identity(&file)
        .map(Ok)
        .unwrap_or_else(|| pinned_identity(&file));
    if let Some(scanned) = scanned {
        check_same_scanned_file(scanned, mapped.clone().map(|mapped| mapped.identity))?;
    }
    let mapped = mapped.ok();
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
            return Entry::new(
                file,
                before,
                raw.path.clone(),
                &inspected,
                raw,
                found,
                mapped,
            );
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
    Entry::new(
        file,
        before,
        raw.path.clone(),
        &inspected,
        raw,
        found,
        mapped,
    )
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
            mapped: None,
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
            mapped: None,
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

    /// Records the object an open `fd` names, so a later check can prove
    /// the descriptor was closed without depending on the number staying
    /// free: parallel tests in the same process reuse fd numbers
    /// immediately, so `fcntl(fd, F_GETFD) == -1` after a drop is a race.
    /// Panics when `fd` is not open; call before the close/drop.
    pub(crate) fn record_open_fd(fd: std::os::fd::RawFd) -> (u64, u64) {
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fstat only reads; `fd` is open by contract.
        assert_eq!(
            unsafe { libc::fstat(fd, &mut stat) },
            0,
            "record_open_fd needs an open fd, got {fd}"
        );
        (stat.st_dev as u64, stat.st_ino as u64)
    }

    /// Proves `fd` was closed after `record_open_fd`: the number is either
    /// free (fstat fails EBADF) or names a different object. Panics when
    /// the number still names the recorded object, which is exactly the
    /// skipped-close shape.
    ///
    /// Sound only while no other live object shares the recorded
    /// (st_dev, st_ino): record a unique object, e.g. a pinned
    /// `NamedTempFile` whose live link keeps its inode from being
    /// recycled. Never use this for pidfds: every pidfd to one pid
    /// shares one identity (see `PidfdClosureWitness`).
    pub(crate) fn assert_fd_closed(fd: std::os::fd::RawFd, recorded: (u64, u64)) {
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fstat only reads; `fd` may be closed or reused by now.
        if unsafe { libc::fstat(fd, &mut stat) } != 0 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EBADF),
                "fstat on fd {fd} failed without EBADF"
            );
            return;
        }
        assert_ne!(
            (stat.st_dev as u64, stat.st_ino as u64),
            recorded,
            "fd {fd} still names the recorded object; the close was skipped"
        );
    }

    /// Proves a pidfd was closed without depending on the number staying
    /// free. Every pidfd to one pid shares one (st_dev, st_ino), so
    /// `assert_fd_closed` cannot tell the original from another test's
    /// pidfd to the same process; instead this holds a duplicate of the
    /// same open file description and compares with `kcmp KCMP_FILE`
    /// (same-process, needs no privilege): afterwards the number is
    /// either free (EBADF) or names a different description.
    pub(crate) struct PidfdClosureWitness {
        fd: std::os::fd::RawFd,
        witness: std::os::fd::OwnedFd,
    }

    impl PidfdClosureWitness {
        /// Duplicates `fd` as the comparison witness; the dup succeeding
        /// proves `fd` is open. Call before the close/drop.
        pub(crate) fn record(fd: std::os::fd::BorrowedFd<'_>) -> Self {
            use std::os::fd::AsRawFd as _;
            let raw = fd.as_raw_fd();
            let witness = fd
                .try_clone_to_owned()
                .expect("witness dup needs an open fd");
            Self { fd: raw, witness }
        }

        /// Proves the recorded pidfd was closed: panics when the number
        /// still names the same open file description (the skipped-close
        /// shape), or when the probe itself fails.
        pub(crate) fn assert_closed(&self) {
            use std::os::fd::AsRawFd as _;
            const KCMP_FILE: libc::c_long = 0;
            let pid = std::process::id() as libc::c_long;
            // SAFETY: a pure same-process comparison; sends nothing.
            let compared = unsafe {
                libc::syscall(
                    libc::SYS_kcmp,
                    pid,
                    pid,
                    KCMP_FILE,
                    self.fd as libc::c_long,
                    self.witness.as_raw_fd() as libc::c_long,
                )
            };
            assert_ne!(
                compared, 0,
                "fd {} still names the same open file description; the close was skipped",
                self.fd
            );
            if compared < 0 {
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EBADF),
                    "the kcmp probe itself failed"
                );
            }
            // compared > 0: the number now names a different open file
            // description, so the recorded pidfd was closed.
        }
    }

    /// Attaches the scan-time ownership a `real_scan_pin` + `absorb` fixture
    /// bypasses: the view's `ownership.pins` entry and its `raw_ownership`
    /// row. Runs exactly the two inserts `record_scanned_candidate` performs
    /// for an accepted entry; panics when the key/path names no pinned raw.
    pub(crate) fn record_scan_ownership(
        pins: &mut PinnedObjects,
        view: ProcessViewId,
        key: ObjectKey,
        path: &str,
    ) {
        let normalized =
            super::normalize_target_path(path).expect("test ownership path normalizes");
        let (raw, id) = pins
            .raw_to_id
            .iter()
            .find(|(raw, _)| raw.key == key && raw.path == normalized)
            .map(|(raw, id)| (raw.clone(), *id))
            .expect("test key/path names a pinned raw");
        pins.ownership.entry(view).or_default().pins.push(id);
        pins.raw_ownership.entry(view).or_default().insert(raw);
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
            mapped: None,
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
            mapped: None,
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

    #[test]
    fn retained_target_charge_is_bounded_before_the_first_copy() {
        let mut pins = test_fixture::real_scan_pin(
            Path::new("/usr/bin/true"),
            None,
            1,
            "bank-pre-copy-charge",
        );
        let id = pins.pinned().next().unwrap().id;
        assert_eq!(
            pins.retained_target_copy_allocation_charge(PinnedObjectId(u32::MAX)),
            None
        );
        let entry = pins.by_id.get_mut(&id).unwrap();
        entry.raw.path = String::with_capacity(4096);
        entry.raw.path.push_str("/raw/namespace/provider.so");
        entry.path = String::with_capacity(1024);
        entry.path.push_str("/display/provider.so");
        entry.sha256.reserve(2048);
        entry.build_id = Some(String::with_capacity(512));
        entry.build_id.as_mut().unwrap().push_str("owned-build-id");
        let before = pins.revision();
        let bound = pins.retained_target_copy_allocation_charge(id).unwrap();
        let original = &pins.by_id[&id];
        let expected = [
            Some(&original.raw.path),
            Some(&original.path),
            Some(&original.sha256),
            original.build_id.as_ref(),
        ]
        .into_iter()
        .flatten()
        .map(|text| text.capacity() + 32)
        .sum::<usize>();
        assert_eq!(bound, expected);
        assert!(
            bound > pins.summary(id).unwrap().path.len() + 1024,
            "raw namespace text and spare capacities must be included"
        );
        assert_eq!(pins.revision(), before, "preallocation lookup is read-only");
        let retained = pins.retain_inventory_target(id).unwrap();
        assert!(
            retained.retained_copy_allocation_charge().unwrap() <= bound,
            "fresh String clones may trim capacity, but cannot exceed the pre-copy bound"
        );
        assert_eq!(retained.entry.raw.path, "/raw/namespace/provider.so");
        assert_eq!(retained.entry.path, "/display/provider.so");
        assert_eq!(pins.revision(), before);
    }

    #[test]
    fn retained_provider_copy_charge_covers_each_actual_cloned_allocation() {
        let pins = test_fixture::real_scan_pin(
            Path::new("/usr/bin/true"),
            None,
            1,
            "provider-copy-charge",
        );
        let id = pins.pinned().next().unwrap().id;
        let mut target = pins.retain_inventory_target(id).unwrap();
        target.entry.raw.path.reserve(129);
        target.entry.path.reserve(257);
        target.entry.sha256.reserve(513);
        let mut build_id = String::with_capacity(128);
        build_id.push_str("a-real-owned-build-id");
        target.entry.build_id = Some(build_id);
        for allocation_case in 0..3 {
            match allocation_case {
                1 => target.entry.build_id = None,
                2 => {
                    // Tiny fresh allocations also exercise the pinned clone
                    // bound; these strings are allocation inputs, not proof.
                    target.entry.raw.path = "r".to_owned();
                    target.entry.path = "p".to_owned();
                    target.entry.sha256 = "s".to_owned();
                    target.entry.build_id = Some("b".to_owned());
                }
                _ => {}
            }
            let charge = target.retained_copy_allocation_charge().unwrap();
            let copy = target.share();
            let sources = [
                Some(&target.entry.raw.path),
                Some(&target.entry.path),
                Some(&target.entry.sha256),
                target.entry.build_id.as_ref(),
            ];
            let copies = [
                Some(&copy.entry.raw.path),
                Some(&copy.entry.path),
                Some(&copy.entry.sha256),
                copy.entry.build_id.as_ref(),
            ];
            let mut actual = 0;
            let mut expected = 0;
            for (source, copy) in sources.into_iter().zip(copies) {
                assert_eq!(source.is_some(), copy.is_some());
                if let (Some(source), Some(copy)) = (source, copy) {
                    assert_eq!(source, copy);
                    assert!(
                        copy.capacity() <= source.capacity(),
                        "pinned fresh String clone bound"
                    );
                    if !source.is_empty() {
                        assert_ne!(source.as_ptr(), copy.as_ptr());
                    }
                    if source.capacity() != 0 {
                        expected += source.capacity()
                            + crate::semantics_edge::resources::OWNED_ALLOCATION_PADDING;
                    }
                    if copy.capacity() != 0 {
                        actual += copy.capacity()
                            + crate::semantics_edge::resources::OWNED_ALLOCATION_PADDING;
                    }
                }
            }
            assert_eq!(
                charge, expected,
                "both independently cloned path fields are included"
            );
            assert!(charge >= actual);
            assert!(Arc::ptr_eq(&target.entry.file, &copy.entry.file));
            assert!(Arc::ptr_eq(&target.entry.exports, &copy.entry.exports));
        }
    }

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
    fn retained_mapped_identity_keeps_the_original_file_and_rejects_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("held.so");
        let other = dir.path().join("other.so");
        std::fs::write(&path, "same bytes").unwrap();
        std::fs::copy(&path, &other).unwrap();
        let mut pins = test_fixture::real_scan_pin(&path, None, 1, "digest");
        let entry = pins.by_id.values_mut().next().unwrap();
        // Script only the privileged calibration result. Its device differs
        // from fstat, ensuring reuse returns that proof, not a new identity
        // invented from a path, raw maps key or the lookup metadata.
        let calibrated = MappedFile {
            identity: FileIdentity { dev: 37, ino: 9 },
            fs_magic: Some(0x9123_683e),
        };
        entry.mapped = Some(calibrated);
        let original = Arc::downgrade(&entry.file);
        let id = pins.by_id.keys().next().copied().unwrap();
        let target = pins.retain_inventory_target(id).unwrap();
        let snapshot = RetainedMappedIdentities::from_targets([&target, &target]);
        assert_eq!(snapshot.files.len(), 1, "aliases share one retained proof");
        drop(target);
        drop(pins);
        assert!(original.upgrade().is_some(), "the original Arc stays held");

        let reopened = std::fs::File::open(&path).unwrap();
        assert_eq!(snapshot.identity_for(&reopened), Some(calibrated));
        assert_eq!(
            snapshot.identity_for(&std::fs::File::open(&other).unwrap()),
            None
        );
        // The held inode changes through a second open descriptor.
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(format!("/proc/self/fd/{}", reopened.as_raw_fd()))
            .unwrap();
        writer.set_len(32).unwrap();
        assert_eq!(snapshot.identity_for(&reopened), None);
        std::fs::rename(&other, &path).unwrap();
        assert_eq!(
            snapshot.identity_for(&std::fs::File::open(&path).unwrap()),
            None
        );
        drop(snapshot);
        assert!(original.upgrade().is_none());
    }

    #[test]
    fn retained_mapped_identity_refuses_overlay_unknown_and_unproved_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("held.so");
        std::fs::write(&path, "provider").unwrap();
        let mut pins = test_fixture::real_scan_pin(&path, None, 1, "digest");
        let id = pins.by_id.keys().next().copied().unwrap();
        let file = std::fs::File::open(&path).unwrap();
        for (magic, overlay, collapsed, expected) in [
            (Some(0xef53), false, false, true),
            (Some(0x9123_683e), false, false, true),
            (Some(0xef53), true, false, false),
            (Some(0xef53), false, true, false),
            (Some(0x794c_7630), false, false, false),
            (Some(0x0102_1994), false, false, false),
            (Some(0x6573_5546), false, false, false),
            (Some(0x1234_5678), false, false, false),
            (None, false, false, false),
        ] {
            let entry = pins.by_id.get_mut(&id).unwrap();
            entry.mapped = Some(MappedFile {
                identity: FileIdentity { dev: 37, ino: 9 },
                fs_magic: magic,
            });
            entry.overlay = overlay;
            entry.collapsed = collapsed;
            let target = pins.retain_inventory_target(id).unwrap();
            let snapshot = RetainedMappedIdentities::from_targets([&target]);
            assert_eq!(
                snapshot.identity_for(&file).is_some(),
                expected,
                "{magic:?}, overlay={overlay}, collapsed={collapsed}"
            );
        }
        pins.by_id.get_mut(&id).unwrap().mapped = None;
        let target = pins.retain_inventory_target(id).unwrap();
        assert!(
            RetainedMappedIdentities::from_targets([&target])
                .files
                .is_empty()
        );
    }

    #[test]
    fn a_retained_pin_reuses_calibration_but_still_checks_the_scanned_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("libpinned.so");
        std::fs::copy("/bin/sh", &path).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let mapping = mapping_file_key(&file).unwrap();
        let view = ProcessView::open(ProcessViewId(0), std::process::id()).unwrap();
        let calibrated = MappedFile {
            identity: FileIdentity { dev: 37, ino: 9 },
            fs_magic: Some(0x9123_683e),
        };
        let mut module = test_fixture::module(object_key(mapping));
        module.view = view.id();
        module.mount_namespace = view.mount_namespace();
        module.path = path.display().to_string();
        module.tables.clear();
        module.mapped_identity = Some(calibrated.identity);
        let (pins, skipped) = pin_scanned_view_objects_with(
            &view,
            std::slice::from_ref(&module),
            &mut CaptureWorkBudget::default(),
            &|_| Ok(calibrated),
        )
        .unwrap();
        assert!(skipped.is_empty(), "{skipped:?}");
        let id = pins.pinned().next().unwrap().id;
        let target = pins.retain_inventory_target(id).unwrap();
        let reusable = pins.by_id[&id].reusable_mapped_file().is_some();
        let probes = std::cell::Cell::new(0);
        let probe = |_: &std::fs::File| {
            probes.set(probes.get() + 1);
            Ok(calibrated)
        };
        let mut budget = CaptureWorkBudget::default()
            .with_retained_mapped_identities(RetainedMappedIdentities::from_targets([&target]));
        let (reused, skipped) = pin_scanned_view_objects_with(
            &view,
            std::slice::from_ref(&module),
            &mut budget,
            &probe,
        )
        .unwrap();
        assert!(skipped.is_empty(), "{skipped:?}");
        assert_eq!(probes.get(), usize::from(!reusable));
        // Sweep matching uses the same retained proof, without a third probe.
        if reusable {
            assert_eq!(
                reused.object_mapped_identity(reused.pinned().next().unwrap().id),
                Ok(calibrated)
            );
        }
        module.mapped_identity = Some(FileIdentity { dev: 47, ino: 9 });
        let (refused, skipped) =
            pin_scanned_view_objects_with(&view, &[module], &mut budget, &probe).unwrap();
        assert_eq!(probes.get(), 2 * usize::from(!reusable));
        assert_eq!(refused.pinned().count(), 0);
        assert!(
            skipped
                .iter()
                .any(|skip| skip.reason.contains("identity_mismatch"))
        );
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
                &|_| {
                    pinned.clone().map(|identity| MappedFile {
                        identity,
                        fs_magic: None,
                    })
                },
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
    #[ignore = "manual: indicative map_files-name timing loop, no pass/fail bar; run by hand single-threaded"]
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
                // `f_type` is signed on glibc and unsigned on musl; the magic fits both.
                #[allow(clippy::unnecessary_cast)]
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

    pub(super) fn conservative_cursor_fixture()
    -> (tempfile::TempDir, PinnedObjects, Vec<ScannedModule>) {
        let dir = tempfile::tempdir().unwrap();
        let mut source = PinnedObjects::empty();
        let mut modules = Vec::new();
        for index in 0..3 {
            let path = dir.path().join(format!("provider-{index}.so"));
            std::fs::copy("/usr/bin/true", &path).unwrap();
            let view = ProcessView::open(ProcessViewId(index + 1), std::process::id()).unwrap();
            // Btrfs st_dev names the subvolume, unlike maps/mountinfo. Obtain
            // the actual comparable key through the SAME retained view before
            // sending the row through ordinary opened-file pin validation.
            let key = view_object_key(&view, &path, &mut CaptureWorkBudget::default()).unwrap();
            let mut scanned = module(key);
            scanned.view = view.id();
            scanned.mount_namespace = view.mount_namespace();
            scanned.path = path.to_str().unwrap().into();
            for table in &mut scanned.tables {
                for entry in &mut table.entries {
                    entry.object_path = scanned.path.clone();
                }
            }
            let (pins, skipped) = pin_scanned_view_objects(
                &view,
                std::slice::from_ref(&scanned),
                &mut CaptureWorkBudget::default(),
            )
            .unwrap();
            assert!(skipped.is_empty(), "{skipped:?}");
            assert!(source.absorb(pins).is_empty());
            modules.push(scanned);
        }
        // A second ACTUAL process-view pin shares the first opened provider.
        // The controlled table rows exercise value transformation only; they
        // do not constitute a bootstrap/attachment receipt.
        let view = ProcessView::open(ProcessViewId(2), std::process::id()).unwrap();
        let mut shared = modules[0].clone();
        shared.view = view.id();
        let (pins, skipped) = pin_scanned_view_objects(
            &view,
            std::slice::from_ref(&shared),
            &mut CaptureWorkBudget::default(),
        )
        .unwrap();
        assert!(skipped.is_empty());
        assert!(source.absorb(pins).is_empty());
        modules.push(shared);
        assert!(bind_scanned_modules(&modules, &mut source).1.is_empty());
        let entry = source.by_id.values_mut().next().unwrap();
        entry.path.reserve(3000);
        entry.build_id = Some("nested-owned-build-id".repeat(64));
        (dir, source, modules)
    }

    fn conservative_selection(
        pool: &crate::semantics_edge::resources::SemanticResourcePool,
        retired: BTreeSet<ProcessViewId>,
        rejected: BTreeSet<ObjectKey>,
    ) -> ConservativePinSelection {
        let bytes = ConservativePinSelection::storage_bound(retired.len(), rejected.len()).unwrap();
        let storage = pool.reserve(bytes).unwrap();
        ConservativePinSelection::from_reserved_originals(
            retired,
            rejected,
            storage,
            &pool.reserver(),
        )
        .unwrap()
    }

    fn assert_conservative_value(expected: &PinnedObjects, actual: &PinnedObjects) {
        assert_eq!(actual.raw_to_id, expected.raw_to_id);
        assert_eq!(actual.rejected_keys, expected.rejected_keys);
        assert_eq!(actual.ambiguous_keys, expected.ambiguous_keys);
        assert_eq!(actual.ambiguity_published, expected.ambiguity_published);
        assert_eq!(actual.ownership, expected.ownership);
        assert_eq!(actual.raw_ownership, expected.raw_ownership);
        assert_eq!(actual.next_id, expected.next_id);
        assert_eq!(actual.overlay_uncertain, expected.overlay_uncertain);
        assert_eq!(actual.changed.get(), expected.changed.get());
        assert_eq!(actual.revision(), expected.revision());
        assert_eq!(actual.by_id.len(), expected.by_id.len());
        for (id, old) in &expected.by_id {
            let new = &actual.by_id[id];
            assert_eq!(new.raw, old.raw);
            assert_eq!(new.mapping, old.mapping);
            assert_eq!(new.pin, old.pin);
            assert_eq!(new.mapped, old.mapped);
            assert_eq!(new.path, old.path);
            assert_eq!(new.sha256, old.sha256);
            assert_eq!(new.build_id, old.build_id);
            assert_eq!(new.abi, old.abi);
            assert_eq!(new.overlay, old.overlay);
            assert_eq!(new.collapsed, old.collapsed);
            assert!(
                Arc::ptr_eq(&new.file, &old.file),
                "the SAME opened File is retained"
            );
            assert!(Arc::ptr_eq(&new.exports, &old.exports));
        }
    }

    fn finish_conservative_copy(
        source: &PinnedObjects,
        cursor: &mut PinnedConservativeCursor,
        selection: &ConservativePinSelection,
        reserve: &crate::semantics_edge::resources::SemanticResourceReserver,
    ) {
        for _ in 0..4096 {
            if source
                .poll_conservative_copy(cursor, selection, reserve, 1)
                .unwrap()
                == GraphStep::Ready
            {
                return;
            }
        }
        panic!("the tiny real-file copy must finish over bounded credits");
    }

    #[test]
    fn conservative_copy_cursor_preserves_originals_and_peak() {
        use crate::semantics_edge::resources::SemanticResourcePool;
        let (_dir, source, modules) = conservative_cursor_fixture();
        let rejected = modules[1].key;
        let pool = SemanticResourcePool::default();
        let selection = conservative_selection(
            &pool,
            BTreeSet::from([ProcessViewId(1)]),
            BTreeSet::from([rejected]),
        );
        let reserve = pool.reserver();
        let mut expected = source.clone();
        expected.remove_view(ProcessViewId(1));
        let expected_skipped = expected.reapply_rejected_keys(&BTreeSet::from([rejected]));
        let source_revision = source.revision();
        let initial_charge = pool.snapshot().charged_bytes;
        let mut cursor = PinnedConservativeCursor::new();
        let (zero, allocations, bytes) = crate::test_alloc::count_allocs_during(|| {
            source.poll_conservative_copy(&mut cursor, &selection, &reserve, 0)
        });
        assert_eq!(zero.unwrap(), GraphStep::Yielded);
        assert_eq!((allocations, bytes), (0, 0));
        assert_eq!(pool.snapshot().charged_bytes, initial_charge);
        assert!(cursor.pinned().is_none());
        let ((), peak) = crate::test_alloc::requested_peak_during(|| {
            for _ in 0..4096 {
                let mut before = [0usize; 3];
                for (count, entry) in before.iter_mut().zip(source.by_id.values()) {
                    *count = Arc::strong_count(&entry.file);
                }
                let step = source
                    .poll_conservative_copy(&mut cursor, &selection, &reserve, 1)
                    .unwrap();
                for (old, entry) in before.into_iter().zip(source.by_id.values()) {
                    assert!(Arc::strong_count(&entry.file).saturating_sub(old) <= 1);
                }
                if step == GraphStep::Ready {
                    break;
                }
            }
            let copy = cursor
                .pinned()
                .expect("bounded copy becomes structurally Ready");
            assert_conservative_value(&expected, copy);
            assert_eq!(cursor.skipped().unwrap(), expected_skipped);
            assert_eq!(source.revision(), source_revision);
            assert!(
                source
                    .by_id
                    .values()
                    .all(|entry| pin_of(&entry.file).unwrap() == entry.pin)
            );
            assert!(pool.snapshot().charged_bytes > initial_charge);
            // Ready borrows remain paid; no swap/take can strand canonical backing.
            for _ in 0..4096 {
                if cursor
                    .reclaim(Some(&source), &selection, &reserve, 1)
                    .unwrap()
                    == GraphStep::Ready
                {
                    break;
                }
            }
            assert!(cursor.pinned().is_none());
            assert_eq!(pool.snapshot().charged_bytes, initial_charge);
        });
        assert!(!peak.incomplete);
        assert_eq!(
            peak.live_bytes, 0,
            "all copied backing dies before its payment refunds"
        );
        assert_eq!(
            peak.live_blocks, 0,
            "empty B-tree roots are real retained allocations"
        );
        assert!(
            cursor.required_bytes().unwrap() >= peak.realloc_overlap_bytes.max(peak.peak_bytes)
        );
    }

    #[test]
    fn conservative_copy_cursor_refuses_changed_resume_fences() {
        use crate::semantics_edge::resources::SemanticResourcePool;
        for change in 0..7 {
            let (_dir, mut source, _) = conservative_cursor_fixture();
            let pool = SemanticResourcePool::default();
            let reserve = pool.reserver();
            let selection = conservative_selection(
                &pool,
                BTreeSet::from([ProcessViewId(1), ProcessViewId(9), ProcessViewId(20)]),
                BTreeSet::new(),
            );
            let mut cursor = PinnedConservativeCursor::new();
            assert_ne!(
                source
                    .poll_conservative_copy(&mut cursor, &selection, &reserve, 1)
                    .unwrap(),
                GraphStep::Ready
            );
            let foreign = source.clone();
            let other_selection = conservative_selection(
                &pool,
                BTreeSet::from([ProcessViewId(1), ProcessViewId(10), ProcessViewId(20)]),
                BTreeSet::new(),
            );
            let other_pool = SemanticResourcePool::default();
            let error = match change {
                0 => foreign.poll_conservative_copy(&mut cursor, &selection, &reserve, 1),
                1 => {
                    let membership = source.revision();
                    source.reset_derived_claims();
                    assert_eq!(source.revision(), membership);
                    source.poll_conservative_copy(&mut cursor, &selection, &reserve, 1)
                }
                2 => {
                    source.changed.set(true);
                    source.poll_conservative_copy(&mut cursor, &selection, &reserve, 1)
                }
                3 => source.poll_conservative_copy(&mut cursor, &other_selection, &reserve, 1),
                4 => source.poll_conservative_copy(
                    &mut cursor,
                    &selection,
                    &other_pool.reserver(),
                    1,
                ),
                5 => {
                    let membership = source.revision();
                    source.reset_scan_pin_claims();
                    assert_eq!(source.revision(), membership);
                    source.poll_conservative_copy(&mut cursor, &selection, &reserve, 1)
                }
                _ => {
                    source.revision = u64::MAX;
                    source.poll_conservative_copy(&mut cursor, &selection, &reserve, 1)
                }
            };
            assert!(matches!(
                error,
                Err(GraphRefusal::SourceChanged | GraphRefusal::Identity)
            ));
            assert!(cursor.pinned().is_none());
            if change == 0 || change == 3 || change == 4 {
                finish_conservative_copy(&source, &mut cursor, &selection, &reserve);
                assert!(
                    cursor.pinned().is_some(),
                    "foreign calls cannot consume the correct source's work"
                );
            }
        }
    }

    #[test]
    fn conservative_copy_cursor_exact_fit_short_and_overflow() {
        use crate::semantics_edge::resources::SemanticResourcePool;
        assert!(ConservativePinSelection::storage_bound(usize::MAX, 0).is_none());
        assert!(
            conservative_pin_tree_bytes::<RawObjectInstance, PinnedObjectId>(usize::MAX).is_none()
        );
        // Packaging is not authority: reject foreign/short actual payment,
        // returning the SAME immutable original sets and lease untouched.
        for foreign in [false, true] {
            let owner = SemanticResourcePool::default();
            let other = SemanticResourcePool::default();
            let retired = BTreeSet::from([ProcessViewId(3)]);
            let rejected = BTreeSet::new();
            let required = ConservativePinSelection::storage_bound(1, 0).unwrap();
            let storage = owner
                .reserve(if foreign { required } else { required - 1 })
                .unwrap();
            let reserve = if foreign {
                other.reserver()
            } else {
                owner.reserver()
            };
            let charged = owner.snapshot().charged_bytes;
            let refusal = ConservativePinSelection::from_reserved_originals(
                retired, rejected, storage, &reserve,
            )
            .unwrap_err();
            assert_eq!(owner.snapshot().charged_bytes, charged);
            let (retired, rejected, storage) = refusal.into_originals();
            assert_eq!(retired, BTreeSet::from([ProcessViewId(3)]));
            assert!(rejected.is_empty());
            assert!(owner.reserver().covers(&storage, required - 1));
            assert_eq!(owner.snapshot().charged_bytes, charged);
        }
        let (_dir, source, _) = conservative_cursor_fixture();
        let pool = SemanticResourcePool::default();
        let reserve = pool.reserver();
        let selection = conservative_selection(&pool, BTreeSet::new(), BTreeSet::new());
        let baseline = pool.snapshot().charged_bytes;
        let mut cursor = PinnedConservativeCursor::new();
        for _ in 0..4096 {
            if cursor.required_bytes().is_some() {
                break;
            }
            assert_ne!(
                source
                    .poll_conservative_copy(&mut cursor, &selection, &reserve, 1)
                    .unwrap(),
                GraphStep::Ready
            );
        }
        let required = cursor
            .required_bytes()
            .expect("actual measured storage envelope");
        pool.reference_set_limit(baseline.checked_add(required).unwrap() - 1);
        let counts: Vec<_> = source
            .by_id
            .values()
            .map(|entry| Arc::strong_count(&entry.file))
            .collect();
        let mut refused = false;
        for _ in 0..4096 {
            match source.poll_conservative_copy(&mut cursor, &selection, &reserve, 1) {
                Err(GraphRefusal::Storage(_)) => {
                    refused = true;
                    break;
                }
                Ok(step) => assert_ne!(step, GraphStep::Ready),
                Err(other) => panic!("unexpected copy refusal: {other:?}"),
            }
        }
        assert!(refused);
        assert!(cursor.pinned().is_none());
        assert_eq!(
            counts,
            source
                .by_id
                .values()
                .map(|entry| Arc::strong_count(&entry.file))
                .collect::<Vec<_>>()
        );
        pool.reference_set_limit(baseline.checked_add(required).unwrap());
        finish_conservative_copy(&source, &mut cursor, &selection, &reserve);
        assert_conservative_value(&source, cursor.pinned().unwrap());
        assert_eq!(pool.snapshot().charged_bytes, baseline + required);
        for _ in 0..4096 {
            if cursor
                .reclaim(Some(&source), &selection, &reserve, 1)
                .unwrap()
                == GraphStep::Ready
            {
                break;
            }
        }
        assert_eq!(pool.snapshot().charged_bytes, baseline);
    }

    #[test]
    fn conservative_copy_cursor_refuses_final_file_close() {
        use crate::semantics_edge::resources::SemanticResourcePool;
        let (_dir, source, _) = conservative_cursor_fixture();
        let id = *source.by_id.keys().next().unwrap();
        let actual_fd = source.file_for(id).unwrap().as_raw_fd();
        let pool = SemanticResourcePool::default();
        let reserve = pool.reserver();
        let selection = conservative_selection(&pool, BTreeSet::new(), BTreeSet::new());
        let baseline = pool.snapshot().charged_bytes;
        let mut cursor = PinnedConservativeCursor::new();
        finish_conservative_copy(&source, &mut cursor, &selection, &reserve);
        drop(source);
        // There is now no borrowed or separately retained share of this real
        // File. Reclamation may free copied text, but it cannot close the FD.
        for _ in 0..4096 {
            if cursor.retained_reclaim_file_for_test(id) == Some((4, Some(actual_fd))) {
                break;
            }
            assert_ne!(
                cursor.reclaim(None, &selection, &reserve, 1).unwrap(),
                GraphStep::Ready,
            );
        }
        let before = cursor.retained_reclaim_file_for_test(id);
        assert_eq!(before, Some((4, Some(actual_fd))));
        let held = pool.snapshot().charged_bytes;
        assert!(held > baseline);
        assert_eq!(
            cursor.reclaim(None, &selection, &reserve, 0).unwrap(),
            GraphStep::Yielded
        );
        assert_eq!(cursor.retained_reclaim_file_for_test(id), before);
        assert_eq!(pool.snapshot().charged_bytes, held);
        assert!(
            matches!(
                cursor.reclaim(None, &selection, &reserve, 1),
                Err(GraphRefusal::Identity)
            ),
            "no borrowed matching File alias permits a synchronous final close"
        );
        assert_eq!(cursor.retained_reclaim_file_for_test(id), before);
        assert_eq!(pool.snapshot().charged_bytes, held);
        // SAFETY: F_GETFD observes the original descriptor; no open/poll/native
        // work between dropping the source and this check can replace its slot.
        assert!(unsafe { libc::fcntl(actual_fd, libc::F_GETFD) } >= 0);
        assert!(cursor.pinned().is_none());
        // The paid cursor is intentionally still retained here. Eventual final
        // File handoff/abandonment belongs to the later Engine/native port.
    }

    #[test]
    fn conservative_copy_cursor_reclaims_unique_nested_and_guarded_shared_arc() {
        use crate::semantics_edge::resources::SemanticResourcePool;
        let (_dir, mut source, _) = conservative_cursor_fixture();
        let id = *source.by_id.keys().next().unwrap();
        source.by_id.get_mut(&id).unwrap().exports = Arc::from(vec![
            ("controlled-first-label".repeat(8), 1),
            ("controlled-second-label".repeat(16), 2),
            ("controlled-third-label".repeat(32), 3),
        ]);
        let pool = SemanticResourcePool::default();
        let reserve = pool.reserver();
        // Only this entry's unique export backing is under test. Other real
        // entries are conservatively rejected before copying, so their final
        // File owners are not an unrelated pending handoff in this control.
        let rejected = source
            .by_id
            .iter()
            .filter_map(|(other, entry)| (*other != id).then_some(entry.raw.key))
            .collect();
        let selection = conservative_selection(&pool, BTreeSet::new(), rejected);
        let baseline = pool.snapshot().charged_bytes;
        let mut cursor = PinnedConservativeCursor::new();
        finish_conservative_copy(&source, &mut cursor, &selection, &reserve);
        assert_eq!(cursor.pinned().unwrap().by_id.len(), 1);
        let alias = source.exports_for(id);
        // Settle our File share under the borrowed LIVE actual source, then
        // stop BEFORE touching its exports. No final FD close is delegated to
        // the pure helper when the source goes away below.
        for _ in 0..4096 {
            let step = cursor
                .reclaim(Some(&source), &selection, &reserve, 1)
                .unwrap();
            assert_ne!(step, GraphStep::Ready);
            if cursor.retained_reclaim_file_for_test(id) == Some((5, None)) {
                break;
            }
        }
        assert_eq!(cursor.retained_reclaim_file_for_test(id), Some((5, None)));
        assert_eq!(cursor.retained_exports_for_test(id).unwrap().len(), 3);
        drop(source);
        let held = pool.snapshot().charged_bytes;
        let mut shared_refusal = false;
        for _ in 0..4096 {
            match cursor.reclaim(None, &selection, &reserve, 1) {
                Err(GraphRefusal::Identity) => {
                    shared_refusal = true;
                    break;
                }
                Ok(step) => assert_ne!(step, GraphStep::Ready),
                Err(other) => panic!("unexpected reclamation refusal: {other:?}"),
            }
        }
        assert!(
            shared_refusal,
            "an unknown shared last-drop race retains actual paid ownership"
        );
        assert!(pool.snapshot().charged_bytes > baseline);
        assert!(pool.snapshot().charged_bytes <= held);
        assert_eq!(alias.iter().filter(|(text, _)| !text.is_empty()).count(), 3);
        let weak = Arc::downgrade(&alias);
        drop(alias);
        assert!(matches!(
            cursor.reclaim(None, &selection, &reserve, 1),
            Err(GraphRefusal::Identity)
        ));
        assert!(pool.snapshot().charged_bytes > baseline);
        drop(weak);
        let mut prior = 3usize;
        for _ in 0..4096 {
            let step = cursor.reclaim(None, &selection, &reserve, 1).unwrap();
            let left = cursor.retained_exports_for_test(id).map_or(0, |exports| {
                exports.iter().filter(|(text, _)| !text.is_empty()).count()
            });
            assert!(
                prior.saturating_sub(left) <= 1,
                "one credit cannot destroy the complete nested array"
            );
            prior = left;
            if step == GraphStep::Ready {
                break;
            }
        }
        assert_eq!(prior, 0);
        assert_eq!(pool.snapshot().charged_bytes, baseline);
    }

    #[test]
    fn conservative_copy_cache_exhaustion_preserves_legacy_clone() {
        use crate::semantics_edge::resources::SemanticResourcePool;
        use std::sync::atomic::AtomicU64;
        let counter = AtomicU64::new(u64::MAX - 1);
        assert!(mint_pin_copy_cache_id(&counter).is_some());
        assert!(mint_pin_copy_cache_id(&counter).is_none());
        assert!(mint_pin_copy_cache_id(&counter).is_none());
        let (_dir, mut source, _) = conservative_cursor_fixture();
        let ordinary = source.clone();
        assert!(source.copy_source != ordinary.copy_source);
        assert_conservative_value(&source, &ordinary);
        source.copy_source = None;
        let legacy = source.clone();
        assert_conservative_value(&source, &legacy);
        let pool = SemanticResourcePool::default();
        let reserve = pool.reserver();
        let selection = conservative_selection(&pool, BTreeSet::new(), BTreeSet::new());
        let mut cursor = PinnedConservativeCursor::new();
        let charged = pool.snapshot().charged_bytes;
        let (answer, allocations, _) = crate::test_alloc::count_allocs_during(|| {
            source.poll_conservative_copy(&mut cursor, &selection, &reserve, 1)
        });
        assert!(matches!(answer, Err(GraphRefusal::Identity)));
        assert_eq!(allocations, 0);
        assert_eq!(pool.snapshot().charged_bytes, charged);
        assert!(cursor.pinned().is_none());
    }

    #[test]
    fn conservative_copy_final_slice_release_does_not_walk_drained_elements() {
        use std::mem::{ManuallyDrop, align_of, needs_drop, size_of};
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Resource-free: suppressing this destructor cannot leak a payload.
        struct DropProbe;
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        impl Drop for DropProbe {
            fn drop(&mut self) {
                DROPS.fetch_add(1, Ordering::Relaxed);
            }
        }
        const {
            assert!(needs_drop::<(String, u64)>());
            assert!(!needs_drop::<ManuallyDrop<(String, u64)>>());
            assert!(size_of::<(String, u64)>() == size_of::<ManuallyDrop<(String, u64)>>());
            assert!(align_of::<(String, u64)>() == align_of::<ManuallyDrop<(String, u64)>>());
        }
        let mut probes: Arc<[DropProbe]> = Arc::from([DropProbe, DropProbe, DropProbe]);
        assert!(Arc::get_mut(&mut probes).is_some());
        // SAFETY: resource-free elements, actual unique allocation/no Weak,
        // no live borrow or observer between the check and transfer.
        unsafe { deallocate_drained_unique_arc(probes) };
        assert_eq!(DROPS.load(Ordering::Relaxed), 0);

        let ((), peak) = crate::test_alloc::requested_peak_during(|| {
            let mut payloads: Arc<[(String, u64)]> = Arc::from([
                ("one owned allocation".repeat(64), 1),
                ("another owned allocation".repeat(128), 2),
            ]);
            let before = crate::test_alloc::armed_requested_snapshot();
            for item in Arc::get_mut(&mut payloads).unwrap() {
                drop(std::mem::take(&mut item.0));
                assert_eq!(item.0.capacity(), 0);
            }
            let drained = crate::test_alloc::armed_requested_snapshot();
            assert_eq!(before.live_blocks - drained.live_blocks, 2);
            assert!(before.live_bytes > drained.live_bytes);
            assert!(
                drained.live_bytes > 0,
                "the SAME slice allocation is still held"
            );
            assert!(Arc::get_mut(&mut payloads).is_some());
            // SAFETY: every payload has actually been freed above. Remaining
            // elements are valid zero-capacity Strings plus integers, exclusive
            // with no Weak; the final release skips their typed Drop loop.
            unsafe { deallocate_drained_unique_arc(payloads) };
        });
        assert!(!peak.incomplete);
        assert_eq!(peak.live_bytes, 0);
        assert_eq!(peak.live_blocks, 0);
    }

    fn retained_rebind_inputs(
        pool: &crate::semantics_edge::resources::SemanticResourcePool,
        originals: &[ScannedModule],
        short_backing: bool,
    ) -> (Option<RetainedScannedInputs>, usize) {
        // Real owned rows derived from the same normal pin fixture. Measure
        // the actual heterogeneous retained requests; no production bound or
        // receipt is supplied by this test-only input setup.
        let (owned, peak) = crate::test_alloc::requested_peak_during(|| {
            let mut owned = originals.to_vec();
            owned.reserve(7);
            if let Some(first) = owned.first_mut() {
                first.path.reserve(113);
                first.exports.reserve(5);
                if let Some(table) = first.tables.first_mut() {
                    table.entries.reserve(9);
                }
            }
            owned
        });
        assert!(!peak.incomplete);
        let storage_bytes = peak
            .live_bytes
            .checked_add(peak.live_blocks.checked_mul(64).unwrap())
            .unwrap()
            .checked_add(4096)
            .unwrap();
        let storage = pool
            .reserve(if short_backing { 1 } else { storage_bytes })
            .unwrap();
        let original_pointer = owned.as_ptr();
        let original_capacity = owned.capacity();
        let (result, allocations, bytes) = crate::test_alloc::count_allocs_during(|| {
            RetainedScannedInputs::from_reserved_originals(owned, storage)
        });
        assert_eq!(
            (allocations, bytes),
            (0, 0),
            "input packaging is an O(1) move"
        );
        let input = result.unwrap();
        assert_eq!(input.originals_for_test().as_ptr(), original_pointer);
        assert_eq!(input.original_capacity_for_test(), original_capacity);
        (Some(input), storage_bytes)
    }

    fn finish_scanned_rebind(
        pins: &mut PinnedConservativeCursor,
        input: &mut Option<RetainedScannedInputs>,
        rebind: &mut ScannedRebindCursor,
        reserve: &crate::semantics_edge::resources::SemanticResourceReserver,
    ) {
        for _ in 0..4096 {
            if pins.poll_scanned_rebind(input, rebind, reserve, 1).unwrap() == GraphStep::Ready {
                return;
            }
        }
        panic!("the tiny retained scanned originals must bind over finite credits");
    }

    fn rebind_claim_lengths(pins: &PinnedConservativeCursor) -> [(usize, usize, usize); 3] {
        [ProcessViewId(1), ProcessViewId(2), ProcessViewId(3)].map(|view| {
            pins.reference_rebind_claims_for_test(view)
                .map_or((0, 0, 0), |claims| {
                    (claims.tables.len(), claims.targets.len(), claims.pins.len())
                })
        })
    }

    #[test]
    fn scanned_rebind_cursor_matches_original_binding() {
        use crate::semantics_edge::resources::SemanticResourcePool;
        let (_dir, source, mut raw) = conservative_cursor_fixture();
        let missing = raw[2].key;
        let missing_path = raw[2].path.clone();
        // Same actual normalized provider; no filesystem reopen may be hidden
        // in the rebind lookup. Its real pin was accepted before this spelling.
        let canonical = PathBuf::from(&raw[0].path);
        raw[0].path = canonical
            .parent()
            .unwrap()
            .join("unused/../provider-0.so")
            .to_str()
            .unwrap()
            .into();
        raw[0].tables[0].entries[0].object_path = raw[0].path.clone();
        let duplicate = raw[0].tables[0].entries[0].clone();
        raw[0].tables[0]
            .entries
            .extend(std::iter::repeat_n(duplicate.clone(), 12));
        let mut absent_entry = duplicate;
        absent_entry.object = missing;
        absent_entry.object_path = missing_path;
        raw[0].tables[0].entries.push(absent_entry);
        raw[0]
            .exports
            .push("controlled heterogeneous input text".repeat(37));
        raw[0]
            .interfaces
            .push(crate::discovery::scan::ScannedInterface {
                index: 0,
                name_class: "other",
                name_lossy: Some("private fixture name".repeat(9)),
                name_private: Some(vec![1, 2, 3, 4]),
                flags: 0,
                table: Some(0),
            });
        raw[1].decoder_abi = Some(ElfAbi::Ilp32);
        let pool = SemanticResourcePool::default();
        let reserve = pool.reserver();
        let selection = conservative_selection(&pool, BTreeSet::new(), BTreeSet::from([missing]));
        let baseline = pool.snapshot().charged_bytes;
        let mut pins = PinnedConservativeCursor::new();
        finish_conservative_copy(&source, &mut pins, &selection, &reserve);
        let mut expected = pins.pinned().unwrap().clone();
        expected.reset_derived_claims();
        let (expected_modules, expected_skips) = bind_scanned_modules(&raw, &mut expected);
        assert!(!expected_modules.is_empty());
        assert!(
            expected_skips.len() >= 3,
            "entry, ABI, and missing-provider negatives are genuine"
        );
        let (mut input, input_bytes) = retained_rebind_inputs(&pool, &raw, false);
        let pointer = input.as_ref().unwrap().originals_for_test().as_ptr();
        let held = pool.snapshot().charged_bytes;
        let mut rebind = ScannedRebindCursor::new();
        let (zero, allocations, bytes) = crate::test_alloc::count_allocs_during(|| {
            pins.poll_scanned_rebind(&mut input, &mut rebind, &reserve, 0)
        });
        assert_eq!(zero.unwrap(), GraphStep::Yielded);
        assert_eq!((allocations, bytes), (0, 0));
        assert_eq!(pool.snapshot().charged_bytes, held);
        assert_eq!(
            input.as_ref().unwrap().originals_for_test().as_ptr(),
            pointer
        );
        let ((), peak) = crate::test_alloc::requested_peak_during(|| {
            for _ in 0..4096 {
                let before_claims = rebind_claim_lengths(&pins);
                let mut before_refs = [0usize; 3];
                for (count, entry) in before_refs.iter_mut().zip(source.by_id.values()) {
                    *count = Arc::strong_count(&entry.exports);
                }
                let step = pins
                    .poll_scanned_rebind(&mut input, &mut rebind, &reserve, 1)
                    .unwrap();
                let after_claims = rebind_claim_lengths(&pins);
                let changed = before_claims
                    .into_iter()
                    .zip(after_claims)
                    .filter(|(before, after)| before != after)
                    .count();
                assert!(
                    changed <= 1,
                    "one credit cannot reset or bind every process view"
                );
                let growth = before_claims
                    .into_iter()
                    .zip(after_claims)
                    .map(|(before, after)| {
                        after.0.saturating_sub(before.0)
                            + after.1.saturating_sub(before.1)
                            + after.2.saturating_sub(before.2)
                    })
                    .sum::<usize>();
                assert!(
                    growth <= 2,
                    "one entry may add its target+pin, never a whole table of claims"
                );
                for (before, entry) in before_refs.into_iter().zip(source.by_id.values()) {
                    assert!(Arc::strong_count(&entry.exports).saturating_sub(before) <= 1);
                }
                if step == GraphStep::Ready {
                    break;
                }
            }
        });
        assert!(!peak.incomplete);
        assert!(input.is_none(), "the same original Vec was taken once");
        let actual_modules = rebind
            .modules()
            .expect("all originals and claims reach structural readiness");
        assert_eq!(actual_modules, expected_modules);
        assert_eq!(rebind.skipped().unwrap(), expected_skips);
        for (actual, expected) in actual_modules.iter().zip(&expected_modules) {
            assert!(Arc::ptr_eq(&actual.exports, &expected.exports));
            for (actual, expected) in actual.scanned.tables.iter().zip(&expected.scanned.tables) {
                assert_eq!(actual.live_return, expected.live_return);
                assert_eq!(actual.manifest_supported, expected.manifest_supported);
            }
        }
        assert_conservative_value(&expected, pins.pinned().unwrap());
        assert!(rebind.required_input_bytes().unwrap() <= input_bytes);
        assert!(
            rebind.required_bytes().unwrap() >= peak.peak_bytes.max(peak.realloc_overlap_bytes)
        );
        assert_eq!(
            pool.snapshot().charged_bytes,
            held + rebind.required_bytes().unwrap()
        );
        for _ in 0..4096 {
            if rebind.reclaim(Some(&mut pins), &reserve, 1).unwrap() == GraphStep::Ready {
                break;
            }
        }
        assert!(rebind.modules().is_none());
        for _ in 0..4096 {
            if pins
                .reclaim(Some(&source), &selection, &reserve, 1)
                .unwrap()
                == GraphStep::Ready
            {
                break;
            }
        }
        assert_eq!(pool.snapshot().charged_bytes, baseline);
    }

    #[test]
    fn scanned_rebind_cursor_keeps_claim_growth_paid() {
        use crate::semantics_edge::resources::SemanticResourcePool;
        for exit in 0..3 {
            let (_dir, source, mut raw) = conservative_cursor_fixture();
            let entry = raw[0].tables[0].entries[0].clone();
            raw[0].tables[0]
                .entries
                .extend(std::iter::repeat_n(entry, 24));
            let pool = SemanticResourcePool::default();
            let reserve = pool.reserver();
            let selection = conservative_selection(&pool, BTreeSet::new(), BTreeSet::new());
            let baseline = pool.snapshot().charged_bytes;
            let mut pins = PinnedConservativeCursor::new();
            finish_conservative_copy(&source, &mut pins, &selection, &reserve);
            let pin_charge = pool.snapshot().charged_bytes;
            let view = raw[0].view;
            let old_capacity = pins
                .pinned()
                .unwrap()
                .view_claims(view)
                .unwrap()
                .pins
                .capacity();
            let (mut input, _) = retained_rebind_inputs(&pool, &raw, false);
            let mut rebind = ScannedRebindCursor::new();
            for _ in 0..4096 {
                assert_ne!(
                    pins.poll_scanned_rebind(&mut input, &mut rebind, &reserve, 1)
                        .unwrap(),
                    GraphStep::Ready
                );
                if pins
                    .reference_rebind_claims_for_test(view)
                    .is_some_and(|claims| {
                        claims.pins.capacity() > old_capacity && !claims.targets.is_empty()
                    })
                {
                    break;
                }
            }
            assert!(input.is_none());
            assert!(
                pins.pinned().is_none(),
                "partial mutable claims are not a Ready output"
            );
            assert!(
                pins.reference_rebind_claims_for_test(view)
                    .unwrap()
                    .pins
                    .capacity()
                    > old_capacity
            );
            let claim_bytes = rebind.required_claim_bytes().unwrap();
            assert!(claim_bytes > 0);
            if exit == 2 {
                // This tests PAYMENT lifetime only, not a bounded abandonment
                // completion: that separate Engine/native obligation stays open.
                drop(rebind);
                assert_eq!(pool.snapshot().charged_bytes, pin_charge + claim_bytes);
                assert!(pins.pinned().is_none());
                assert!(
                    pins.reference_rebind_claims_for_test(view)
                        .unwrap()
                        .pins
                        .capacity()
                        > old_capacity
                );
                drop(pins);
                assert_eq!(pool.snapshot().charged_bytes, baseline);
                continue;
            }
            if exit == 1 {
                rebind.cancel();
                assert!(matches!(
                    pins.poll_scanned_rebind(&mut input, &mut rebind, &reserve, 1),
                    Err(GraphRefusal::Cancelled)
                ));
                assert!(pins.pinned().is_none());
            } else {
                finish_scanned_rebind(&mut pins, &mut input, &mut rebind, &reserve);
                assert!(rebind.modules().is_some());
            }
            for _ in 0..4096 {
                if rebind.reclaim(Some(&mut pins), &reserve, 1).unwrap() == GraphStep::Ready {
                    break;
                }
            }
            assert!(rebind.modules().is_none());
            drop(rebind);
            assert_eq!(pool.snapshot().charged_bytes, pin_charge + claim_bytes);
            assert!(
                pins.reference_rebind_claims_for_test(view)
                    .unwrap()
                    .pins
                    .capacity()
                    > old_capacity
            );
            for _ in 0..4096 {
                if pins
                    .reclaim(Some(&source), &selection, &reserve, 1)
                    .unwrap()
                    == GraphStep::Ready
                {
                    break;
                }
            }
            assert_eq!(pool.snapshot().charged_bytes, baseline);
        }

        // The module cursor can actually become the last export-slice owner.
        // Keep independent LIVE shares of the SAME Files so this setup does
        // not disguise a final FD close as pure per-credit export reclamation.
        let (_dir, mut source, raw) = conservative_cursor_fixture();
        let id = *source.by_id.keys().next().unwrap();
        source.by_id.get_mut(&id).unwrap().exports = Arc::from(vec![
            ("first retained module label".repeat(8), 1),
            ("second retained module label".repeat(16), 2),
            ("third retained module label".repeat(32), 3),
        ]);
        let file_guards: Vec<_> = source
            .by_id
            .values()
            .map(|entry| entry.file.clone())
            .collect();
        let pool = SemanticResourcePool::default();
        let reserve = pool.reserver();
        let selection = conservative_selection(&pool, BTreeSet::new(), BTreeSet::new());
        let baseline = pool.snapshot().charged_bytes;
        let mut pins = PinnedConservativeCursor::new();
        finish_conservative_copy(&source, &mut pins, &selection, &reserve);
        let (mut input, _) = retained_rebind_inputs(&pool, &raw[..1], false);
        let mut rebind = ScannedRebindCursor::new();
        finish_scanned_rebind(&mut pins, &mut input, &mut rebind, &reserve);
        assert_eq!(rebind.modules().unwrap().len(), 1);
        let alias = source.exports_for(id);
        drop(source);
        drop(pins);
        let mut refused = false;
        for _ in 0..4096 {
            match rebind.reclaim(None, &reserve, 1) {
                Err(GraphRefusal::Identity) => {
                    refused = true;
                    break;
                }
                Ok(step) => assert_ne!(step, GraphStep::Ready),
                Err(other) => panic!("unexpected last-owner refusal: {other:?}"),
            }
        }
        assert!(
            refused,
            "unknown shared exports retain their actual module owner and payment"
        );
        assert_eq!(alias.iter().filter(|(text, _)| !text.is_empty()).count(), 3);
        assert!(pool.snapshot().charged_bytes > baseline);
        let weak = Arc::downgrade(&alias);
        drop(alias);
        assert!(matches!(
            rebind.reclaim(None, &reserve, 1),
            Err(GraphRefusal::Identity)
        ));
        drop(weak);
        let mut prior = 3usize;
        for _ in 0..4096 {
            let step = rebind.reclaim(None, &reserve, 1).unwrap();
            let left = rebind
                .reference_pending_exports_for_test(id)
                .map_or(0, |exports| {
                    exports.iter().filter(|(text, _)| !text.is_empty()).count()
                });
            assert!(prior.saturating_sub(left) <= 1);
            prior = left;
            if step == GraphStep::Ready {
                break;
            }
        }
        assert_eq!(prior, 0);
        assert_eq!(pool.snapshot().charged_bytes, baseline);
        for file in &file_guards {
            // SAFETY: read-only check of each retained actual descriptor.
            assert!(unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) } >= 0);
        }
    }

    #[test]
    fn scanned_rebind_cursor_refuses_changed_inputs_and_short_pool() {
        use crate::semantics_edge::resources::SemanticResourcePool;
        let (_dir, source, raw) = conservative_cursor_fixture();
        let pool = SemanticResourcePool::default();
        let reserve = pool.reserver();
        let selection = conservative_selection(&pool, BTreeSet::new(), BTreeSet::new());
        let mut pins = PinnedConservativeCursor::new();
        finish_conservative_copy(&source, &mut pins, &selection, &reserve);
        let (mut short, _) = retained_rebind_inputs(&pool, &raw, true);
        let pointer = short.as_ref().unwrap().originals_for_test().as_ptr();
        let before = pins.pinned().unwrap().clone();
        let mut invalid = ScannedRebindCursor::new();
        let mut refused = false;
        for _ in 0..4096 {
            match pins.poll_scanned_rebind(&mut short, &mut invalid, &reserve, 1) {
                Err(GraphRefusal::Identity) => {
                    refused = true;
                    break;
                }
                Ok(step) => assert_ne!(step, GraphStep::Ready),
                Err(other) => panic!("unexpected input-backing refusal: {other:?}"),
            }
        }
        assert!(refused);
        assert!(invalid.required_input_bytes().unwrap() > 1);
        assert_eq!(
            short.as_ref().unwrap().originals_for_test().as_ptr(),
            pointer
        );
        assert_conservative_value(&before, pins.pinned().unwrap());
        for _ in 0..4096 {
            if invalid.reclaim(Some(&mut pins), &reserve, 1).unwrap() == GraphStep::Ready {
                break;
            }
        }
        drop(invalid);
        let original = short.take().unwrap();
        let (rows, lease) = original.into_originals();
        assert_eq!(rows.as_ptr(), pointer);
        assert!(reserve.covers(&lease, 1));
        drop(rows);
        drop(lease);

        let (mut input, _) = retained_rebind_inputs(&pool, &raw, false);
        let mut rebind = ScannedRebindCursor::new();
        pins.poll_scanned_rebind(&mut input, &mut rebind, &reserve, 1)
            .unwrap();
        assert!(input.is_some());
        // Equal-valued pins from the SAME original source remain a different
        // private candidate allocation. They cannot take this cursor/input.
        let mut foreign_pins = PinnedConservativeCursor::new();
        finish_conservative_copy(&source, &mut foreign_pins, &selection, &reserve);
        let held = pool.snapshot().charged_bytes;
        assert!(matches!(
            foreign_pins.poll_scanned_rebind(&mut input, &mut rebind, &reserve, 1),
            Err(GraphRefusal::Identity)
        ));
        assert!(input.is_some());
        assert_eq!(pool.snapshot().charged_bytes, held);
        assert_conservative_value(&before, foreign_pins.pinned().unwrap());
        drop(foreign_pins);
        let pointer = input.as_ref().unwrap().originals_for_test().as_ptr();
        let (rows, lease) = input.take().unwrap().into_originals();
        input = Some(RetainedScannedInputs::from_reserved_originals(rows, lease).unwrap());
        assert_eq!(
            input.as_ref().unwrap().originals_for_test().as_ptr(),
            pointer
        );
        assert!(
            matches!(
                pins.poll_scanned_rebind(&mut input, &mut rebind, &reserve, 1),
                Err(GraphRefusal::Identity)
            ),
            "consuming/re-wrapping the SAME allocation cannot inherit an earlier sizing cursor"
        );
        for _ in 0..4096 {
            if rebind.reclaim(Some(&mut pins), &reserve, 1).unwrap() == GraphStep::Ready {
                break;
            }
        }
        drop(rebind);
        let mut rebind = ScannedRebindCursor::new();
        let before_rebind = pool.snapshot().charged_bytes;
        let other = SemanticResourcePool::default();
        let (foreign, allocations, bytes) = crate::test_alloc::count_allocs_during(|| {
            pins.poll_scanned_rebind(&mut input, &mut rebind, &other.reserver(), 1)
        });
        assert!(matches!(foreign, Err(GraphRefusal::Identity)));
        assert_eq!((allocations, bytes), (0, 0));
        assert!(input.is_some());
        assert_eq!(pool.snapshot().charged_bytes, before_rebind);
        for _ in 0..4096 {
            if rebind.required_bytes().is_some() {
                break;
            }
            assert_ne!(
                pins.poll_scanned_rebind(&mut input, &mut rebind, &reserve, 1)
                    .unwrap(),
                GraphStep::Ready
            );
        }
        let required = rebind.required_bytes().unwrap();
        assert!(required > 1);
        pool.reference_set_limit(before_rebind.checked_add(required).unwrap() - 1);
        let mut refused = false;
        for _ in 0..4096 {
            match pins.poll_scanned_rebind(&mut input, &mut rebind, &reserve, 1) {
                Err(GraphRefusal::Storage(_)) => {
                    refused = true;
                    break;
                }
                Ok(step) => assert_ne!(step, GraphStep::Ready),
                Err(other) => panic!("unexpected output/claim refusal: {other:?}"),
            }
        }
        assert!(refused);
        assert!(
            input.is_some(),
            "precharge refusal takes no original and resets no claims"
        );
        assert_conservative_value(&before, pins.pinned().unwrap());
        pool.reference_set_limit(before_rebind.checked_add(required).unwrap());
        finish_scanned_rebind(&mut pins, &mut input, &mut rebind, &reserve);
        assert!(input.is_none());
        assert_eq!(pool.snapshot().charged_bytes, before_rebind + required);
        assert!(rebind.modules().is_some());
    }

    #[test]
    fn scanned_rebind_cursor_moves_retained_pin_prefix_over_credits() {
        use crate::semantics_edge::resources::SemanticResourcePool;
        for cancel in [false, true] {
            let (_dir, mut source, raw) = conservative_cursor_fixture();
            let repeated: Vec<_> = std::iter::repeat_n(raw[0].clone(), 64).collect();
            assert!(bind_scanned_modules(&repeated, &mut source).1.is_empty());
            let view = raw[0].view;
            let expected_prefix = source.view_claims(view).unwrap().pins.clone();
            assert!(expected_prefix.len() > 64);
            let pool = SemanticResourcePool::default();
            let reserve = pool.reserver();
            let selection = conservative_selection(&pool, BTreeSet::new(), BTreeSet::new());
            let baseline = pool.snapshot().charged_bytes;
            let (mut input, _) = retained_rebind_inputs(&pool, &raw[..1], false);
            let mut pins = PinnedConservativeCursor::new();
            let mut rebind = ScannedRebindCursor::new();
            let mut observed_growth = false;
            let mut released_original = false;
            let ((), peak) = crate::test_alloc::requested_peak_during(|| {
                finish_conservative_copy(&source, &mut pins, &selection, &reserve);
                let old_capacity = pins
                    .pinned()
                    .unwrap()
                    .view_claims(view)
                    .unwrap()
                    .pins
                    .capacity();
                let old_bytes = old_capacity * std::mem::size_of::<PinnedObjectId>();
                let mut previous = 0usize;
                for _ in 0..4096 {
                    let before = crate::test_alloc::armed_requested_snapshot();
                    let step = pins
                        .poll_scanned_rebind(&mut input, &mut rebind, &reserve, 1)
                        .unwrap();
                    let after = crate::test_alloc::armed_requested_snapshot();
                    let actual = &pins.reference_rebind_claims_for_test(view).unwrap().pins;
                    if !observed_growth && actual.capacity() > old_capacity {
                        observed_growth = true;
                        assert!(
                            actual.len() <= 1,
                            "a populated pin prefix cannot move in its allocation credit"
                        );
                        let new_bytes = actual.capacity() * std::mem::size_of::<PinnedObjectId>();
                        assert!(
                            after.live_bytes >= before.live_bytes + new_bytes,
                            "the old actual pin allocation remains held alongside fresh backing"
                        );
                        previous = actual.len();
                    } else if observed_growth && previous < expected_prefix.len() {
                        assert!(
                            actual.len() <= previous + 1,
                            "work1 moves at most one original pin claim"
                        );
                        previous = actual.len();
                    }
                    if observed_growth {
                        let prefix = actual.len().min(expected_prefix.len());
                        assert_eq!(&actual[..prefix], &expected_prefix[..prefix]);
                        if actual.len() >= expected_prefix.len()
                            && before.live_bytes.saturating_sub(after.live_bytes) >= old_bytes
                        {
                            released_original = true;
                        }
                    }

                    if cancel
                        && observed_growth
                        && !actual.is_empty()
                        && actual.len() < expected_prefix.len()
                    {
                        let current = &pins.reference_rebind_claims_for_test(view).unwrap().pins;
                        let custody = (current.as_ptr(), current.len(), current.capacity());
                        let held = pool.snapshot();
                        let allocated = crate::test_alloc::armed_requested_snapshot();
                        let pending = (
                            input.is_none(),
                            pins.pinned().is_none(),
                            rebind.modules().is_none(),
                        );
                        assert_eq!(pending, (true, true, true));
                        assert!(matches!(
                            rebind.reclaim(None, &reserve, 1),
                            Err(GraphRefusal::Identity)
                        ));
                        let current = &pins.reference_rebind_claims_for_test(view).unwrap().pins;
                        assert_eq!(
                            (current.as_ptr(), current.len(), current.capacity()),
                            custody
                        );
                        assert_eq!(&current[..], &expected_prefix[..current.len()]);
                        assert_eq!(pool.snapshot(), held);
                        assert_eq!(crate::test_alloc::armed_requested_snapshot(), allocated);
                        // Normal binding still advances: ownerless refusal did not switch the
                        // original live transfer into its reclaim phase.
                        assert_eq!(
                            pins.poll_scanned_rebind(&mut input, &mut rebind, &reserve, 1)
                                .unwrap(),
                            GraphStep::Advanced
                        );
                        let current = &pins.reference_rebind_claims_for_test(view).unwrap().pins;
                        assert!(!current.is_empty() && current.len() < expected_prefix.len());
                        assert_eq!(&current[..], &expected_prefix[..current.len()]);
                        let custody = (current.as_ptr(), current.len(), current.capacity());
                        rebind.cancel();
                        let held = pool.snapshot();
                        let allocated = crate::test_alloc::armed_requested_snapshot();
                        assert!(matches!(
                            rebind.reclaim(None, &reserve, 1),
                            Err(GraphRefusal::Identity)
                        ));
                        let current = &pins.reference_rebind_claims_for_test(view).unwrap().pins;
                        assert_eq!(
                            (current.as_ptr(), current.len(), current.capacity()),
                            custody
                        );
                        assert_eq!(&current[..], &expected_prefix[..current.len()]);
                        assert_eq!(
                            (
                                input.is_none(),
                                pins.pinned().is_none(),
                                rebind.modules().is_none()
                            ),
                            pending
                        );
                        assert_eq!(pool.snapshot(), held);
                        assert_eq!(crate::test_alloc::armed_requested_snapshot(), allocated);
                        assert!(matches!(
                            pins.poll_scanned_rebind(&mut input, &mut rebind, &reserve, 1),
                            Err(GraphRefusal::Cancelled)
                        ));
                        break;
                    }
                    if step == GraphStep::Ready {
                        break;
                    }
                }
                assert!(observed_growth);
                if cancel {
                    assert!(rebind.modules().is_none());
                } else {
                    assert!(released_original);
                    assert!(rebind.modules().is_some());
                }
                for _ in 0..4096 {
                    let before = crate::test_alloc::armed_requested_snapshot();
                    let step = rebind.reclaim(Some(&mut pins), &reserve, 1).unwrap();
                    let after = crate::test_alloc::armed_requested_snapshot();
                    assert!(
                        before.live_blocks.saturating_sub(after.live_blocks) <= 1,
                        "work1 cancellation cannot destroy a populated original suffix"
                    );
                    if before.live_bytes.saturating_sub(after.live_bytes) >= old_bytes {
                        released_original = true;
                    }
                    if step == GraphStep::Ready {
                        break;
                    }
                }
                assert!(released_original);
                for _ in 0..4096 {
                    if pins
                        .reclaim(Some(&source), &selection, &reserve, 1)
                        .unwrap()
                        == GraphStep::Ready
                    {
                        break;
                    }
                }
            });
            assert!(!peak.incomplete);
            assert_eq!(peak.live_bytes, 0);
            assert_eq!(peak.live_blocks, 0);
            assert_eq!(pool.snapshot().charged_bytes, baseline);
        }
    }

    #[test]
    fn scanned_rebind_cursor_moves_original_skip_prefix_over_credits() {
        use crate::semantics_edge::resources::SemanticResourcePool;
        for cancel in [false, true] {
            let (_dir, mut source, raw) = conservative_cursor_fixture();
            source.reject_observation(raw[2].key);
            let mut negative = raw[0].clone();
            negative.tables[0].entries.clear();
            for ordinal in 0..64 {
                let mut entry = raw[0].tables[0].entries[0].clone();
                entry.object = raw[2].key;
                entry.object_path = format!(
                    "{}/unused-{ordinal}/../provider-2.so",
                    Path::new(&raw[2].path).parent().unwrap().display()
                );
                negative.tables[0].entries.push(entry);
            }
            // These are original, actual ordinary-binder negative records, with
            // distinct owned path reasons; no scalar debt or readiness is seeded.
            let (mut bound, skipped) = bind_scanned_modules(&[negative], &mut source);
            assert_eq!(skipped.len(), 64);
            let mut original = bound.remove(0).scanned;
            let expected_prefix = original.tables[0].unpinned.clone();
            assert_eq!(expected_prefix.len(), 64);
            let mut entry = raw[0].tables[0].entries[0].clone();
            entry.object = raw[2].key;
            entry.object_path = raw[2].path.clone();
            original.tables[0].entries.push(entry);
            let originals = [original];
            let pool = SemanticResourcePool::default();
            let reserve = pool.reserver();
            let selection = conservative_selection(&pool, BTreeSet::new(), BTreeSet::new());
            let baseline = pool.snapshot().charged_bytes;
            // Establish the retained-request envelope with the existing allocator
            // oracle, then admit a same-shape actual copy BEFORE its allocation.
            let (prepared, _) = retained_rebind_inputs(&pool, &originals, false);
            let (prepared_rows, storage) = prepared.unwrap().into_originals();
            drop(prepared_rows);
            let mut pins = PinnedConservativeCursor::new();
            let mut rebind = ScannedRebindCursor::new();
            let mut observed_growth = false;
            let mut released_original = false;
            let ((), peak) = crate::test_alloc::requested_peak_during(|| {
                let rows = originals.to_vec();
                let mut input =
                    Some(RetainedScannedInputs::from_reserved_originals(rows, storage).unwrap());
                finish_conservative_copy(&source, &mut pins, &selection, &reserve);
                let old_capacity = input.as_ref().unwrap().originals_for_test()[0].tables[0]
                    .unpinned
                    .capacity();
                assert_eq!(
                    old_capacity,
                    expected_prefix.len(),
                    "the actual owned clone has a tight prefix"
                );
                let old_bytes = old_capacity * std::mem::size_of::<Skipped>();
                let mut previous = 0usize;
                for _ in 0..4096 {
                    let before = crate::test_alloc::armed_requested_snapshot();
                    let step = pins
                        .poll_scanned_rebind(&mut input, &mut rebind, &reserve, 1)
                        .unwrap();
                    let after = crate::test_alloc::armed_requested_snapshot();
                    if let Some((capacity, actual)) = rebind.reference_current_unpinned_for_test() {
                        if !observed_growth && capacity > old_capacity {
                            observed_growth = true;
                            assert!(
                                actual.len() <= 1,
                                "allocation cannot copy the complete original skip prefix"
                            );
                            assert!(
                                after.live_bytes
                                    >= before.live_bytes
                                        + capacity * std::mem::size_of::<Skipped>(),
                                "old and fresh actual skip buffers overlap until prefix transfer finishes"
                            );
                            previous = actual.len();
                        } else if observed_growth && previous < expected_prefix.len() {
                            assert!(
                                actual.len() <= previous + 1,
                                "work1 moves at most one original skip record"
                            );
                            previous = actual.len();
                        }
                        if observed_growth {
                            let prefix = actual.len().min(expected_prefix.len());
                            assert_eq!(&actual[..prefix], &expected_prefix[..prefix]);
                            if actual.len() >= expected_prefix.len()
                                && before.live_bytes.saturating_sub(after.live_bytes) >= old_bytes
                            {
                                released_original = true;
                            }
                        }

                        if cancel
                            && observed_growth
                            && !actual.is_empty()
                            && actual.len() < expected_prefix.len()
                        {
                            let (capacity, current) =
                                rebind.reference_current_unpinned_for_test().unwrap();
                            let custody = (current.as_ptr(), current.len(), capacity);
                            let held = pool.snapshot();
                            let allocated = crate::test_alloc::armed_requested_snapshot();
                            let pending = (
                                input.is_none(),
                                pins.pinned().is_none(),
                                rebind.modules().is_none(),
                            );
                            assert_eq!(pending, (true, true, true));
                            assert!(matches!(
                                rebind.reclaim(None, &reserve, 1),
                                Err(GraphRefusal::Identity)
                            ));
                            let (capacity, current) =
                                rebind.reference_current_unpinned_for_test().unwrap();
                            assert_eq!((current.as_ptr(), current.len(), capacity), custody);
                            assert_eq!(current, &expected_prefix[..current.len()]);
                            assert_eq!(pool.snapshot(), held);
                            assert_eq!(crate::test_alloc::armed_requested_snapshot(), allocated);
                            // Normal binding still advances: ownerless refusal did not switch the
                            // original live transfer into its reclaim phase.
                            assert_eq!(
                                pins.poll_scanned_rebind(&mut input, &mut rebind, &reserve, 1)
                                    .unwrap(),
                                GraphStep::Advanced
                            );
                            let (capacity, current) =
                                rebind.reference_current_unpinned_for_test().unwrap();
                            assert!(!current.is_empty() && current.len() < expected_prefix.len());
                            assert_eq!(current, &expected_prefix[..current.len()]);
                            let custody = (current.as_ptr(), current.len(), capacity);
                            rebind.cancel();
                            let held = pool.snapshot();
                            let allocated = crate::test_alloc::armed_requested_snapshot();
                            assert!(matches!(
                                rebind.reclaim(None, &reserve, 1),
                                Err(GraphRefusal::Identity)
                            ));
                            let (capacity, current) =
                                rebind.reference_current_unpinned_for_test().unwrap();
                            assert_eq!((current.as_ptr(), current.len(), capacity), custody);
                            assert_eq!(current, &expected_prefix[..current.len()]);
                            assert_eq!(
                                (
                                    input.is_none(),
                                    pins.pinned().is_none(),
                                    rebind.modules().is_none()
                                ),
                                pending
                            );
                            assert_eq!(pool.snapshot(), held);
                            assert_eq!(crate::test_alloc::armed_requested_snapshot(), allocated);
                            assert!(matches!(
                                pins.poll_scanned_rebind(&mut input, &mut rebind, &reserve, 1),
                                Err(GraphRefusal::Cancelled)
                            ));
                            break;
                        }
                    }
                    if step == GraphStep::Ready {
                        break;
                    }
                }
                assert!(observed_growth);
                if !cancel {
                    assert!(released_original);
                    let module = &rebind.modules().unwrap()[0];
                    assert_eq!(
                        &module.scanned.tables[0].unpinned[..64],
                        expected_prefix.as_slice()
                    );
                    assert_eq!(module.scanned.tables[0].unpinned.len(), 65);
                    assert_eq!(rebind.skipped().unwrap().len(), 1);
                } else {
                    assert!(rebind.modules().is_none());
                }
                for _ in 0..4096 {
                    let before = crate::test_alloc::armed_requested_snapshot();
                    let step = rebind.reclaim(Some(&mut pins), &reserve, 1).unwrap();
                    let after = crate::test_alloc::armed_requested_snapshot();
                    assert!(
                        before.live_blocks.saturating_sub(after.live_blocks) <= 1,
                        "work1 cancellation cannot destroy a populated original suffix"
                    );
                    if before.live_bytes.saturating_sub(after.live_bytes) >= old_bytes {
                        released_original = true;
                    }
                    if step == GraphStep::Ready {
                        break;
                    }
                }
                assert!(released_original);
                for _ in 0..4096 {
                    if pins
                        .reclaim(Some(&source), &selection, &reserve, 1)
                        .unwrap()
                        == GraphStep::Ready
                    {
                        break;
                    }
                }
            });
            assert!(!peak.incomplete);
            assert_eq!(peak.live_bytes, 0);
            assert_eq!(peak.live_blocks, 0);
            assert_eq!(pool.snapshot().charged_bytes, baseline);
        }
    }

    fn drive_pins_installed_reclaim(
        cursor: &mut PinnedConservativeCursor,
        live: &PinnedObjects,
        selection: &ConservativePinSelection,
        handoff: &mut RetiredFileHandoff,
        reserve: &crate::semantics_edge::resources::SemanticResourceReserver,
    ) -> Result<(), GraphRefusal> {
        for _ in 0..4096 {
            match cursor.reclaim_installed(live, selection, handoff, reserve, 1) {
                Ok(GraphStep::Ready) => return Ok(()),
                Ok(_) => {}
                Err(error) => return Err(error),
            }
        }
        panic!("installed pins reclaim must finish over bounded credits");
    }

    fn drive_rebind_installed_reclaim(
        rebind: &mut ScannedRebindCursor,
        pins: &mut PinnedConservativeCursor,
        live: &PinnedObjects,
        handoff: &mut RetiredFileHandoff,
        reserve: &crate::semantics_edge::resources::SemanticResourceReserver,
    ) -> Result<(), GraphRefusal> {
        for _ in 0..4096 {
            match rebind.reclaim_installed(pins, live, handoff, reserve, 1) {
                Ok(GraphStep::Ready) => return Ok(()),
                Ok(_) => {}
                Err(error) => return Err(error),
            }
        }
        panic!("installed rebind reclaim must finish over bounded credits");
    }

    #[test]
    fn conservative_install_sink_keeps_leases_until_old_canonical_reclaimed() {
        use crate::semantics_edge::resources::SemanticResourcePool;
        let (_dir, source, _) = conservative_cursor_fixture();
        let pool = SemanticResourcePool::default();
        let reserve = pool.reserver();
        let selection = conservative_selection(&pool, BTreeSet::new(), BTreeSet::new());
        let baseline = pool.snapshot().charged_bytes;
        let mut cursor = PinnedConservativeCursor::new();
        finish_conservative_copy(&source, &mut cursor, &selection, &reserve);
        let expected = source.clone();
        let before_install = pool.snapshot().charged_bytes;
        assert!(before_install > baseline);
        let mut canonical = source;
        let installed = cursor.install_ready(&mut canonical);
        assert!(
            installed.is_ok(),
            "install_ready accepts a Ready copy with no loan: {installed:?}"
        );
        let backing = installed.unwrap();
        // The swap moved leases; it refunded nothing.
        assert_eq!(pool.snapshot().charged_bytes, before_install);
        assert_conservative_value(&expected, &canonical);
        // The cursor now holds the old canonical.
        let old = cursor.installed_output_for_test();
        assert!(old.is_some(), "installed cursor retains the old canonical");
        assert_conservative_value(&expected, old.unwrap());
        assert_eq!(cursor.installed_state_for_test(), (true, true));
        assert!(cursor.pinned().is_none());
        assert!(cursor.loaned_output().is_none());
        // Nothing is retired, so every old file is live-aliased and the
        // handoff stays empty while the old canonical is reclaimed.
        assert_eq!(
            cursor.retired_entry_count(),
            None,
            "installed cursor answers no pre-install count"
        );
        let handoff = RetiredFileHandoff::reserve(0, &reserve);
        assert!(handoff.is_ok(), "empty handoff reserves: {handoff:?}");
        let mut handoff = handoff.unwrap();
        let handoff_bytes = RetiredFileHandoff::bytes(0);
        assert_eq!(
            pool.snapshot().charged_bytes,
            before_install + handoff_bytes
        );
        let outcome = drive_pins_installed_reclaim(
            &mut cursor,
            &canonical,
            &selection,
            &mut handoff,
            &reserve,
        );
        assert!(
            outcome.is_ok(),
            "old canonical reclaims against live: {outcome:?}"
        );
        // Leases stay charged through reclaim; only the backing drop refunds.
        assert_eq!(
            pool.snapshot().charged_bytes,
            before_install + handoff_bytes
        );
        assert_eq!(handoff.len_for_test(), 0);
        assert_eq!(cursor.installed_state_for_test(), (false, true));
        drop(handoff);
        assert_eq!(pool.snapshot().charged_bytes, before_install);
        drop(canonical);
        drop(backing);
        assert_eq!(pool.snapshot().charged_bytes, baseline);
    }

    #[test]
    fn conservative_install_sink_refuses_unready_cursor() {
        use crate::semantics_edge::resources::SemanticResourcePool;
        let (_dir, source, raw) = conservative_cursor_fixture();
        let pool = SemanticResourcePool::default();
        let reserve = pool.reserver();
        let selection = conservative_selection(&pool, BTreeSet::new(), BTreeSet::new());
        let baseline = pool.snapshot().charged_bytes;
        let mut canonical = source.clone();
        // Fresh and mid-copy pins cursors are not Ready.
        let mut fresh = PinnedConservativeCursor::new();
        assert!(matches!(
            fresh.install_ready(&mut canonical),
            Err(GraphRefusal::Identity)
        ));
        assert_eq!(pool.snapshot().charged_bytes, baseline);
        let mut partial = PinnedConservativeCursor::new();
        assert_ne!(
            source
                .poll_conservative_copy(&mut partial, &selection, &reserve, 1)
                .unwrap(),
            GraphStep::Ready
        );
        assert!(matches!(
            partial.install_ready(&mut canonical),
            Err(GraphRefusal::Identity)
        ));
        // A refusal consumes nothing: the same cursor still installs at Ready.
        finish_conservative_copy(&source, &mut partial, &selection, &reserve);
        let held = pool.snapshot().charged_bytes;
        let installed = partial.install_ready(&mut canonical);
        assert!(
            installed.is_ok(),
            "refused cursor installs at Ready: {installed:?}"
        );
        let backing = installed.unwrap();
        assert_eq!(pool.snapshot().charged_bytes, held);
        drop(canonical);
        drop(backing);
        assert_eq!(pool.snapshot().charged_bytes, baseline);
        // A reclaimed pins cursor reports Cancelled, not Identity.
        let mut spent = PinnedConservativeCursor::new();
        finish_conservative_copy(&source, &mut spent, &selection, &reserve);
        for _ in 0..4096 {
            if spent
                .reclaim(Some(&source), &selection, &reserve, 1)
                .unwrap()
                == GraphStep::Ready
            {
                break;
            }
        }
        let mut canonical = source.clone();
        assert!(matches!(
            spent.install_ready(&mut canonical),
            Err(GraphRefusal::Cancelled)
        ));
        assert_eq!(pool.snapshot().charged_bytes, baseline);
        // An aborted pins cursor (rebind cancelled mid-bind, loan released).
        let (mut input, _) = retained_rebind_inputs(&pool, &raw, false);
        let mut pins = PinnedConservativeCursor::new();
        finish_conservative_copy(&source, &mut pins, &selection, &reserve);
        let mut aborted = ScannedRebindCursor::new();
        for _ in 0..4096 {
            if input.is_none() {
                break;
            }
            pins.poll_scanned_rebind(&mut input, &mut aborted, &reserve, 1)
                .unwrap();
        }
        assert!(input.is_none(), "admit takes the input before cancel");
        aborted.cancel();
        for _ in 0..4096 {
            if aborted.reclaim(Some(&mut pins), &reserve, 1).unwrap() == GraphStep::Ready {
                break;
            }
        }
        assert!(matches!(
            pins.install_ready(&mut canonical),
            Err(GraphRefusal::Cancelled)
        ));
        drop(aborted);
        drop(pins);
        // Rebind sink: fresh, mid-bind and cancelled refuse without charging.
        let (mut input2, _) = retained_rebind_inputs(&pool, &raw, false);
        let mut pins2 = PinnedConservativeCursor::new();
        finish_conservative_copy(&source, &mut pins2, &selection, &reserve);
        let mut rebind = ScannedRebindCursor::new();
        let mut modules = Vec::new();
        let charged = pool.snapshot().charged_bytes;
        assert!(matches!(
            rebind.install_ready(&mut modules),
            Err(GraphRefusal::Identity)
        ));
        assert_eq!(pool.snapshot().charged_bytes, charged);
        pins2
            .poll_scanned_rebind(&mut input2, &mut rebind, &reserve, 1)
            .unwrap();
        let charged = pool.snapshot().charged_bytes;
        assert!(matches!(
            rebind.install_ready(&mut modules),
            Err(GraphRefusal::Identity)
        ));
        assert_eq!(pool.snapshot().charged_bytes, charged);
        rebind.cancel();
        assert!(matches!(
            rebind.install_ready(&mut modules),
            Err(GraphRefusal::Cancelled)
        ));
        assert_eq!(pool.snapshot().charged_bytes, charged);
        // A reclaimed rebind reports Cancelled.
        let (mut input3, _) = retained_rebind_inputs(&pool, &raw, false);
        let mut pins3 = PinnedConservativeCursor::new();
        finish_conservative_copy(&source, &mut pins3, &selection, &reserve);
        let mut done = ScannedRebindCursor::new();
        finish_scanned_rebind(&mut pins3, &mut input3, &mut done, &reserve);
        for _ in 0..4096 {
            if done.reclaim(Some(&mut pins3), &reserve, 1).unwrap() == GraphStep::Ready {
                break;
            }
        }
        let charged = pool.snapshot().charged_bytes;
        assert!(matches!(
            done.install_ready(&mut modules),
            Err(GraphRefusal::Cancelled)
        ));
        assert_eq!(pool.snapshot().charged_bytes, charged);
        drop(done);
        drop(pins3);
        drop(input3);
        // A Ready rebind installs, moving its payment into the backing.
        let (mut input4, _) = retained_rebind_inputs(&pool, &raw, false);
        let mut pins4 = PinnedConservativeCursor::new();
        finish_conservative_copy(&source, &mut pins4, &selection, &reserve);
        let mut ready = ScannedRebindCursor::new();
        finish_scanned_rebind(&mut pins4, &mut input4, &mut ready, &reserve);
        assert!(input4.is_none());
        let held = pool.snapshot().charged_bytes;
        let installed = ready.install_ready(&mut modules);
        assert!(installed.is_ok(), "Ready rebind installs: {installed:?}");
        let backing = installed.unwrap();
        assert_eq!(pool.snapshot().charged_bytes, held);
        assert!(!modules.is_empty(), "installed modules reach the canonical");
        drop(modules);
        drop(ready);
        drop(pins4);
        drop(backing);
    }

    #[test]
    fn conservative_installed_reclaim_hands_off_absent_files_and_releases_live_aliases() {
        use crate::semantics_edge::resources::SemanticResourcePool;
        let (_dir, source, _) = conservative_cursor_fixture();
        let pool = SemanticResourcePool::default();
        let reserve = pool.reserver();
        let selection = conservative_selection(
            &pool,
            BTreeSet::from([ProcessViewId(2), ProcessViewId(3)]),
            BTreeSet::new(),
        );
        let id_for = |provider: &str| {
            source
                .by_id
                .iter()
                .find(|(_, entry)| entry.path.contains(provider))
                .map(|(id, _)| *id)
                .unwrap()
        };
        let id_a = id_for("provider-0");
        let id_r1 = id_for("provider-1");
        let id_r2 = id_for("provider-2");
        // Sanity: A is claimed by surviving view 1; R ids only by retired views.
        let surviving: BTreeSet<PinnedObjectId> = source
            .ownership
            .iter()
            .filter(|(view, _)| **view == ProcessViewId(1))
            .flat_map(|(_, claims)| {
                claims
                    .tables
                    .iter()
                    .chain(claims.pins.iter())
                    .copied()
                    .chain(claims.targets.iter().map(|(id, _)| *id))
            })
            .collect();
        assert!(surviving.contains(&id_a));
        assert!(!surviving.contains(&id_r1) && !surviving.contains(&id_r2));
        let retired_claims: BTreeSet<PinnedObjectId> = source
            .ownership
            .iter()
            .filter(|(view, _)| **view != ProcessViewId(1))
            .flat_map(|(_, claims)| {
                claims
                    .tables
                    .iter()
                    .chain(claims.pins.iter())
                    .copied()
                    .chain(claims.targets.iter().map(|(id, _)| *id))
            })
            .collect();
        let weak_a = Arc::downgrade(&source.by_id.get(&id_a).unwrap().file);
        let weak_r1 = Arc::downgrade(&source.by_id.get(&id_r1).unwrap().file);
        let weak_r2 = Arc::downgrade(&source.by_id.get(&id_r2).unwrap().file);
        let fd_a = source.by_id.get(&id_a).unwrap().file.as_raw_fd();
        let fd_r1 = source.by_id.get(&id_r1).unwrap().file.as_raw_fd();
        let fd_r2 = source.by_id.get(&id_r2).unwrap().file.as_raw_fd();
        let mut cursor = PinnedConservativeCursor::new();
        finish_conservative_copy(&source, &mut cursor, &selection, &reserve);
        {
            let copy = cursor.pinned().unwrap();
            assert!(!copy.by_id.contains_key(&id_r1) && !copy.by_id.contains_key(&id_r2));
            assert!(copy.by_id.contains_key(&id_a));
        }
        // Handoff capacity: removed plus rejected ids of this copy.
        let count = cursor.retired_entry_count();
        assert_eq!(
            count,
            Some(retired_claims.len()),
            "retired count covers every removed claim"
        );
        let handoff = RetiredFileHandoff::reserve(count.unwrap(), &reserve);
        assert!(handoff.is_ok(), "handoff reserves: {handoff:?}");
        let mut handoff = handoff.unwrap();
        let mut canonical = source;
        let installed = cursor.install_ready(&mut canonical);
        assert!(installed.is_ok(), "Ready copy installs: {installed:?}");
        let backing = installed.unwrap();
        assert!(canonical.by_id.contains_key(&id_a));
        assert!(!canonical.by_id.contains_key(&id_r1));
        assert!(!canonical.by_id.contains_key(&id_r2));
        let outcome = drive_pins_installed_reclaim(
            &mut cursor,
            &canonical,
            &selection,
            &mut handoff,
            &reserve,
        );
        assert!(
            outcome.is_ok(),
            "installed reclaim hands off absent files: {outcome:?}"
        );
        // Kept entry: the old share dropped under the live alias.
        assert_eq!(
            weak_a.strong_count(),
            1,
            "live canonical holds the only A share"
        );
        // SAFETY: read-only checks of retained descriptors.
        assert!(unsafe { libc::fcntl(fd_a, libc::F_GETFD) } >= 0);
        // Retired entries: alive in the handoff, FDs still open.
        assert_eq!(handoff.len_for_test(), 2);
        for (weak, fd) in [(&weak_r1, fd_r1), (&weak_r2, fd_r2)] {
            assert!(
                weak.upgrade().is_some(),
                "retired file stays open in the handoff"
            );
            assert!(unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0);
        }
        // Lane-style close: one file per call until the chain is empty.
        let mut calls = 0;
        loop {
            calls += 1;
            if handoff.close_some(1) {
                break;
            }
            assert!(calls < 8, "bounded handoff close");
        }
        assert_eq!(calls, 2, "two files close in two single-file calls");
        assert!(weak_r1.upgrade().is_none() && weak_r2.upgrade().is_none());
        drop(canonical);
        drop(backing);
        drop(handoff);
    }

    #[test]
    fn scanned_installed_reclaim_drains_absent_exports_elementwise() {
        use crate::semantics_edge::resources::SemanticResourcePool;
        let (_dir, mut source, modules) = conservative_cursor_fixture();
        // Retire view 3: provider-2's module is absent from the live output.
        let id_r = source
            .by_id
            .iter()
            .find(|(_, entry)| entry.path.contains("provider-2"))
            .map(|(id, _)| *id)
            .unwrap();
        // Old-canonical modules bind first, cloning this exclusive slice...
        source.by_id.get_mut(&id_r).unwrap().exports = Arc::from(vec![
            ("retired-first-export".repeat(8), 11),
            ("retired-second-export".repeat(16), 22),
            ("retired-third-export".repeat(32), 33),
        ]);
        let mut old_pins = source.clone();
        old_pins.reset_derived_claims();
        let (old_modules, _) = bind_scanned_modules(&modules, &mut old_pins);
        drop(old_pins);
        assert!(old_modules.iter().any(|module| module.object == id_r));
        // ...then the live pins move on, leaving the module the last owner.
        source.by_id.get_mut(&id_r).unwrap().exports =
            Arc::from(vec![("live-successor-export".into(), 44)]);
        let bound_exports = old_modules
            .iter()
            .find(|module| module.object == id_r)
            .unwrap()
            .exports
            .clone();
        assert_eq!(
            Arc::strong_count(&bound_exports),
            2,
            "old module plus this probe hold the only shares"
        );
        drop(bound_exports);
        let pool = SemanticResourcePool::default();
        let reserve = pool.reserver();
        let selection =
            conservative_selection(&pool, BTreeSet::from([ProcessViewId(3)]), BTreeSet::new());
        let mut pins = PinnedConservativeCursor::new();
        finish_conservative_copy(&source, &mut pins, &selection, &reserve);
        assert!(!pins.pinned().unwrap().by_id.contains_key(&id_r));
        // Surviving rows only (retired view excluded, like the Engine filter).
        let rows: Vec<ScannedModule> = modules
            .iter()
            .filter(|module| module.view != ProcessViewId(3))
            .cloned()
            .collect();
        assert_eq!(rows.len(), 3);
        let (mut input, _) = retained_rebind_inputs(&pool, &rows, false);
        let mut rebind = ScannedRebindCursor::new();
        finish_scanned_rebind(&mut pins, &mut input, &mut rebind, &reserve);
        assert!(input.is_none());
        let count = pins.retired_entry_count();
        assert_eq!(count, Some(1), "one retired claim bounds the handoff");
        let handoff = RetiredFileHandoff::reserve(count.unwrap(), &reserve);
        assert!(handoff.is_ok(), "handoff reserves: {handoff:?}");
        let mut handoff = handoff.unwrap();
        let mut canonical = source;
        let mut canonical_modules = old_modules;
        let pins_installed = pins.install_ready(&mut canonical);
        assert!(
            pins_installed.is_ok(),
            "loaned pins install: {pins_installed:?}"
        );
        let pins_backing = pins_installed.unwrap();
        let rebind_installed = rebind.install_ready(&mut canonical_modules);
        assert!(
            rebind_installed.is_ok(),
            "bound rebind installs: {rebind_installed:?}"
        );
        let modules_backing = rebind_installed.unwrap();
        // The retired module's exclusive slice drains one element per credit.
        let mut prior = 3usize;
        let mut done = false;
        let mut error = None;
        for _ in 0..4096 {
            match rebind.reclaim_installed(&mut pins, &canonical, &mut handoff, &reserve, 1) {
                Ok(GraphStep::Ready) => {
                    done = true;
                    break;
                }
                Ok(_) => {}
                Err(refused) => {
                    error = Some(refused);
                    break;
                }
            }
            let left = rebind
                .reference_pending_exports_for_test(id_r)
                .map_or(0, |exports| {
                    exports.iter().filter(|(text, _)| !text.is_empty()).count()
                });
            assert!(
                prior.saturating_sub(left) <= 1,
                "one credit drains at most one export"
            );
            prior = left;
        }
        assert!(
            error.is_none(),
            "installed rebind reclaim refused: {error:?}"
        );
        assert!(done, "installed rebind reclaim reaches Ready");
        assert_eq!(prior, 0, "exclusive slice fully drained");
        assert_eq!(
            handoff.len_for_test(),
            0,
            "module exports never enter the file handoff"
        );
        assert_eq!(pins.installed_state_for_test(), (true, true));
        // The retired file still hands off through the pins step.
        let outcome =
            drive_pins_installed_reclaim(&mut pins, &canonical, &selection, &mut handoff, &reserve);
        assert!(
            outcome.is_ok(),
            "installed pins reclaim hands off the file: {outcome:?}"
        );
        assert_eq!(handoff.len_for_test(), 1);
        drop(canonical);
        drop(canonical_modules);
        drop(pins_backing);
        drop(modules_backing);
        drop(handoff);
    }

    #[test]
    fn conservative_installed_reclaim_refuses_replaced_live_canonical() {
        use crate::semantics_edge::resources::SemanticResourcePool;
        let (_dir, source, _) = conservative_cursor_fixture();
        let pool = SemanticResourcePool::default();
        let reserve = pool.reserver();
        let selection = conservative_selection(&pool, BTreeSet::new(), BTreeSet::new());
        let mut cursor = PinnedConservativeCursor::new();
        finish_conservative_copy(&source, &mut cursor, &selection, &reserve);
        // A non-installed cursor refuses installed reclaim outright.
        let handoff = RetiredFileHandoff::reserve(0, &reserve);
        assert!(handoff.is_ok(), "empty handoff reserves: {handoff:?}");
        let mut handoff = handoff.unwrap();
        assert!(matches!(
            cursor.reclaim_installed(&source, &selection, &mut handoff, &reserve, 1),
            Err(GraphRefusal::Identity)
        ));
        let mut canonical = source;
        let installed = cursor.install_ready(&mut canonical);
        assert!(installed.is_ok(), "Ready copy installs: {installed:?}");
        let backing = installed.unwrap();
        // One credit against the true live canonical advances.
        assert_eq!(
            cursor
                .reclaim_installed(&canonical, &selection, &mut handoff, &reserve, 1)
                .unwrap(),
            GraphStep::Advanced
        );
        // A replaced live canonical (fresh copy identity) refuses.
        let replaced = canonical.clone();
        assert!(matches!(
            cursor.reclaim_installed(&replaced, &selection, &mut handoff, &reserve, 1),
            Err(GraphRefusal::Identity)
        ));
        // The refusal kept every owner: resume against the true live.
        let outcome = drive_pins_installed_reclaim(
            &mut cursor,
            &canonical,
            &selection,
            &mut handoff,
            &reserve,
        );
        assert!(
            outcome.is_ok(),
            "reclaim resumes after refusal: {outcome:?}"
        );
        drop(canonical);
        drop(replaced);
        drop(backing);
        drop(handoff);
    }

    /// One joint-graph round at the identity seam: copy, rebind, install both
    /// into the canonical, then rebind reclaim before pins reclaim. Returns
    /// the round's backings, the post-install charge, and the round-local
    /// selection and handoff charges for exact baseline accounting.
    fn run_graph_round(
        pool: &crate::semantics_edge::resources::SemanticResourcePool,
        canonical: &mut PinnedObjects,
        canonical_modules: &mut Vec<ReconciledModule>,
        rows: &[ScannedModule],
        retired: BTreeSet<ProcessViewId>,
        rejected: BTreeSet<ObjectKey>,
        round: u32,
    ) -> (
        InstalledPinsBacking,
        InstalledModulesBacking,
        usize,
        usize,
        usize,
    ) {
        let reserve = pool.reserver();
        let selection_bytes =
            ConservativePinSelection::storage_bound(retired.len(), rejected.len()).unwrap();
        let selection = conservative_selection(pool, retired.clone(), rejected.clone());
        assert_eq!(
            selection.retired(),
            &retired,
            "round {round}: selection keeps retired views"
        );
        assert_eq!(
            selection.rejected(),
            &rejected,
            "round {round}: selection keeps rejected keys"
        );
        let mut pins = PinnedConservativeCursor::new();
        finish_conservative_copy(canonical, &mut pins, &selection, &reserve);
        let (mut input, _) = retained_rebind_inputs(pool, rows, false);
        let mut rebind = ScannedRebindCursor::new();
        finish_scanned_rebind(&mut pins, &mut input, &mut rebind, &reserve);
        assert!(input.is_none(), "round {round}: rebind takes its input");
        let count = pins.retired_entry_count();
        assert!(
            count.is_some(),
            "round {round}: loaned copy answers a retired count"
        );
        let handoff_bytes = RetiredFileHandoff::bytes(count.unwrap());
        let handoff = RetiredFileHandoff::reserve(count.unwrap(), &reserve);
        assert!(
            handoff.is_ok(),
            "round {round}: handoff reserves: {handoff:?}"
        );
        let mut handoff = handoff.unwrap();
        let pins_installed = pins.install_ready(canonical);
        assert!(
            pins_installed.is_ok(),
            "round {round}: loaned pins install: {pins_installed:?}"
        );
        let pins_backing = pins_installed.unwrap();
        let rebind_installed = rebind.install_ready(canonical_modules);
        assert!(
            rebind_installed.is_ok(),
            "round {round}: bound rebind installs: {rebind_installed:?}"
        );
        let modules_backing = rebind_installed.unwrap();
        let installed_charge = pool.snapshot().charged_bytes;
        // Order: pins reclaim while the loan is outstanding refuses.
        assert!(
            matches!(
                pins.reclaim_installed(canonical, &selection, &mut handoff, &reserve, 1),
                Err(GraphRefusal::Identity)
            ),
            "round {round}: pins reclaim refuses while the loan is held"
        );
        let outcome = drive_rebind_installed_reclaim(
            &mut rebind,
            &mut pins,
            canonical,
            &mut handoff,
            &reserve,
        );
        assert!(
            outcome.is_ok(),
            "round {round}: rebind reclaim releases the loan: {outcome:?}"
        );
        assert_eq!(
            pins.installed_state_for_test(),
            (true, true),
            "round {round}: loan released, phase stays Installed"
        );
        let outcome =
            drive_pins_installed_reclaim(&mut pins, canonical, &selection, &mut handoff, &reserve);
        assert!(
            outcome.is_ok(),
            "round {round}: pins reclaim hands off retired files: {outcome:?}"
        );
        // Lane-style close, then release every round-local owner.
        let mut calls = 0;
        loop {
            calls += 1;
            if handoff.close_some(256) {
                break;
            }
            assert!(calls < 64, "round {round}: bounded handoff close");
        }
        drop(handoff);
        drop(selection);
        drop(pins);
        drop(rebind);
        (
            pins_backing,
            modules_backing,
            installed_charge,
            selection_bytes,
            handoff_bytes,
        )
    }

    #[test]
    fn conservative_graph_install_and_reclaim_returns_pool_to_baseline() {
        use crate::semantics_edge::resources::SemanticResourcePool;
        let (_dir, source, modules) = conservative_cursor_fixture();
        let pool = SemanticResourcePool::default();
        let baseline = pool.snapshot().charged_bytes;
        // Round-0 canonical: all rows bound against the pristine pins.
        let mut canonical = source;
        let mut pins0 = canonical.clone();
        pins0.reset_derived_claims();
        let (canonical_modules_init, skips0) = bind_scanned_modules(&modules, &mut pins0);
        assert!(skips0.is_empty(), "pristine rows all bind: {skips0:?}");
        drop(pins0);
        let mut canonical_modules = canonical_modules_init;
        // Round 1: retire view 1, reject view 2's key.
        let rows1: Vec<ScannedModule> = modules
            .iter()
            .filter(|module| module.view != ProcessViewId(1) && module.key != modules[1].key)
            .cloned()
            .collect();
        assert_eq!(rows1.len(), 2);
        let (pins_backing1, modules_backing1, installed1, sel1, ho1) = run_graph_round(
            &pool,
            &mut canonical,
            &mut canonical_modules,
            &rows1,
            BTreeSet::from([ProcessViewId(1)]),
            BTreeSet::from([modules[1].key]),
            1,
        );
        // Round 1 kept nothing but the live canonical's own leases.
        assert_eq!(pool.snapshot().charged_bytes, installed1 - sel1 - ho1);
        assert!(!canonical.ownership.contains_key(&ProcessViewId(1)));
        // Exact fit for one graph above the live canonical.
        let live1 = pool.snapshot().charged_bytes - baseline;
        let peak1 = pool.snapshot().peak_charged_bytes;
        pool.reference_set_limit(pool.snapshot().charged_bytes + (peak1 - baseline));
        // Round 2: retire view 2 (cumulative filter).
        let rows2: Vec<ScannedModule> = modules
            .iter()
            .filter(|module| {
                module.view != ProcessViewId(1)
                    && module.view != ProcessViewId(2)
                    && module.key != modules[1].key
            })
            .cloned()
            .collect();
        assert_eq!(rows2.len(), 1);
        let (pins_backing2, modules_backing2, installed2, sel2, ho2) = run_graph_round(
            &pool,
            &mut canonical,
            &mut canonical_modules,
            &rows2,
            BTreeSet::from([ProcessViewId(2)]),
            BTreeSet::new(),
            2,
        );
        drop(pins_backing1);
        drop(modules_backing1);
        // Round 2 kept nothing but the new live canonical's own leases.
        assert_eq!(
            pool.snapshot().charged_bytes,
            installed2 - sel2 - ho2 - live1
        );
        assert!(!canonical.ownership.contains_key(&ProcessViewId(2)));
        assert!(canonical.ownership.contains_key(&ProcessViewId(3)));
        // Tidy: live canonical released while still paid, then the bill.
        drop(canonical);
        drop(canonical_modules);
        drop(pins_backing2);
        drop(modules_backing2);
        assert_eq!(pool.snapshot().charged_bytes, baseline);
    }

    #[test]
    fn loaned_output_is_some_only_while_rebinding() {
        use crate::semantics_edge::resources::SemanticResourcePool;
        let (_dir, source, raw) = conservative_cursor_fixture();
        let pool = SemanticResourcePool::default();
        let reserve = pool.reserver();
        let selection = conservative_selection(&pool, BTreeSet::new(), BTreeSet::new());
        let mut pins = PinnedConservativeCursor::new();
        assert!(pins.loaned_output().is_none(), "New loans nothing");
        assert_ne!(
            source
                .poll_conservative_copy(&mut pins, &selection, &reserve, 1)
                .unwrap(),
            GraphStep::Ready
        );
        assert!(pins.loaned_output().is_none(), "mid-copy loans nothing");
        finish_conservative_copy(&source, &mut pins, &selection, &reserve);
        assert!(pins.pinned().is_some());
        assert!(
            pins.loaned_output().is_none(),
            "Ready without a loan loans nothing"
        );
        let expected = pins.pinned().unwrap().clone();
        let (mut input, _) = retained_rebind_inputs(&pool, &raw, false);
        let mut rebind = ScannedRebindCursor::new();
        // Drive to admit (input taken) without finishing.
        for _ in 0..4096 {
            if input.is_none() {
                break;
            }
            assert_ne!(
                pins.poll_scanned_rebind(&mut input, &mut rebind, &reserve, 1)
                    .unwrap(),
                GraphStep::Ready
            );
        }
        assert!(input.is_none(), "admit takes the input");
        assert!(pins.pinned().is_none(), "mid-bind hides the partial output");
        assert!(
            pins.loaned_output().is_some(),
            "admit exposes the loaned output"
        );
        // One more bind credit keeps the loan visible.
        assert_ne!(
            pins.poll_scanned_rebind(&mut input, &mut rebind, &reserve, 1)
                .unwrap(),
            GraphStep::Ready
        );
        assert!(
            pins.loaned_output().is_some(),
            "mid-bind keeps the loan visible"
        );
        finish_scanned_rebind(&mut pins, &mut input, &mut rebind, &reserve);
        assert!(rebind.modules().is_some());
        assert!(
            pins.pinned().is_some(),
            "completed bind keeps the Ready borrow"
        );
        let loaned = pins.loaned_output();
        assert!(loaned.is_some(), "completed bind still holds the loan");
        let mut bound = expected.clone();
        bound.reset_derived_claims();
        let (oracle_modules, _) = bind_scanned_modules(&raw, &mut bound);
        assert_conservative_value(&bound, loaned.unwrap());
        assert_eq!(rebind.modules().unwrap(), &oracle_modules);
        // Release the loan: the output is no longer loaned.
        for _ in 0..4096 {
            if rebind.reclaim(Some(&mut pins), &reserve, 1).unwrap() == GraphStep::Ready {
                break;
            }
        }
        assert!(
            pins.pinned().is_some(),
            "released loan restores the Ready borrow"
        );
        assert!(
            pins.loaned_output().is_none(),
            "released loan loans nothing"
        );
        // Install: neither borrow answers.
        let mut canonical = source.clone();
        let installed = pins.install_ready(&mut canonical);
        assert!(installed.is_ok(), "released pins install: {installed:?}");
        let backing = installed.unwrap();
        assert!(pins.pinned().is_none());
        assert!(
            pins.loaned_output().is_none(),
            "installed output is not a loan"
        );
        drop(canonical);
        drop(backing);
    }

    #[test]
    fn conservative_installed_reclaim_refuses_full_handoff_with_storage() {
        use crate::semantics_edge::resources::SemanticResourcePool;
        let (_dir, source, _) = conservative_cursor_fixture();
        let pool = SemanticResourcePool::default();
        let reserve = pool.reserver();
        let selection = conservative_selection(&pool, BTreeSet::new(), BTreeSet::new());
        let mut cursor = PinnedConservativeCursor::new();
        finish_conservative_copy(&source, &mut cursor, &selection, &reserve);
        let mut canonical = source;
        let installed = cursor.install_ready(&mut canonical);
        assert!(installed.is_ok(), "Ready copy installs: {installed:?}");
        let backing = installed.unwrap();
        // Zero reserved slots: any absent file overflows the handoff.
        let handoff = RetiredFileHandoff::reserve(0, &reserve);
        assert!(handoff.is_ok(), "empty handoff reserves: {handoff:?}");
        let mut handoff = handoff.unwrap();
        // Forge the live canonical: same value identity, a stranger file at
        // the first entry, so the old share has no live alias to drop under.
        let id = *canonical.by_id.keys().next().unwrap();
        let fd = canonical.by_id.get(&id).unwrap().file.as_raw_fd();
        let stranger = canonical.by_id.values().nth(1).unwrap().file.clone();
        assert!(!Arc::ptr_eq(
            &canonical.by_id.get(&id).unwrap().file,
            &stranger
        ));
        canonical.by_id.get_mut(&id).unwrap().file = stranger;
        assert!(matches!(
            drive_pins_installed_reclaim(
                &mut cursor,
                &canonical,
                &selection,
                &mut handoff,
                &reserve
            ),
            Err(GraphRefusal::Storage(_))
        ));
        // The refusal kept every owner: nothing was dropped or pushed.
        assert_eq!(handoff.len_for_test(), 0);
        assert_eq!(cursor.installed_state_for_test(), (true, true));
        assert_eq!(
            cursor.retained_reclaim_file_for_test(id),
            Some((4, Some(fd)))
        );
        drop(canonical);
        drop(backing);
        drop(handoff);
    }

    #[test]
    fn scanned_input_measure_matches_cursor_input_accounting() {
        use crate::semantics_edge::resources::SemanticResourcePool;
        let (_dir, source, raw) = conservative_cursor_fixture();
        let pool = SemanticResourcePool::default();
        let reserve = pool.reserver();
        let selection = conservative_selection(&pool, BTreeSet::new(), BTreeSet::new());
        let mut pins = PinnedConservativeCursor::new();
        finish_conservative_copy(&source, &mut pins, &selection, &reserve);
        let (mut input, _) = retained_rebind_inputs(&pool, &raw, false);
        // Direct unit: one group or element per step, true at module end.
        let capacity = input.as_ref().unwrap().original_capacity_for_test();
        let mut measure = ScannedInputMeasure::new(capacity).unwrap();
        assert!(measure.bytes() > 0, "seeded Vec envelope is positive");
        let mut steps = 0usize;
        for module in input.as_ref().unwrap().originals_for_test() {
            let mut module_steps = 0usize;
            loop {
                steps += 1;
                module_steps += 1;
                assert!(module_steps < 4096, "bounded steps per module");
                if measure.step(module).unwrap() {
                    break;
                }
            }
            assert!(
                module_steps >= 4,
                "header, exports, interfaces, tables measured"
            );
        }
        assert!(steps > raw.len());
        let total = measure.bytes();
        // The cursor charges exactly the same input total for the same rows.
        let mut rebind = ScannedRebindCursor::new();
        finish_scanned_rebind(&mut pins, &mut input, &mut rebind, &reserve);
        let required = rebind.required_input_bytes();
        assert!(
            required.is_some(),
            "bound rebind answers an input requirement"
        );
        assert_eq!(
            required.unwrap(),
            total,
            "cursor input accounting matches the standalone measure"
        );
    }

    #[test]
    fn conservative_tree_bound_covers_std_btree_allocations() {
        fn tight_nodes(entries: usize) -> usize {
            if entries == 0 {
                0
            } else {
                1 + (entries - 1) / 5
            }
        }
        fn expected_bytes<K, V>(entries: usize) -> usize {
            fn align8(bytes: usize) -> usize {
                (bytes + 7) & !7
            }
            let node = 16
                + align8(std::mem::size_of::<K>() * 11)
                + align8(std::mem::size_of::<V>() * 11)
                + 12 * 8
                + crate::semantics_edge::resources::OWNED_ALLOCATION_PADDING;
            tight_nodes(entries) * node
        }
        fn ascending(n: usize) -> Vec<u64> {
            (0..n as u64).collect()
        }
        fn descending(n: usize) -> Vec<u64> {
            (0..n as u64).rev().collect()
        }
        fn xorshifted(n: usize) -> Vec<u64> {
            let mut keys: Vec<u64> = (0..n as u64).collect();
            let mut state = 0x9E3779B97F4A7C15u64;
            for i in (1..n).rev() {
                state ^= state >> 12;
                state ^= state << 25;
                state ^= state >> 27;
                let j = (state.wrapping_mul(0x2545F4914F6CDD1D) >> 32) as usize % (i + 1);
                keys.swap(i, j);
            }
            keys
        }
        fn check_cover<K: Ord, V>(
            entries: usize,
            order: &[u64],
            mut key: impl FnMut(u64) -> K,
            mut value: impl FnMut(u64) -> V,
        ) {
            let bound = conservative_pin_tree_bytes::<K, V>(entries)
                .expect("tight bound fits for the test sizes");
            assert_eq!(
                bound,
                expected_bytes::<K, V>(entries),
                "tight node count for {entries} entries"
            );
            let (map, peak) = crate::test_alloc::requested_peak_during(|| {
                let mut map = std::collections::BTreeMap::new();
                for k in order {
                    map.insert(key(*k), value(*k));
                }
                map
            });
            assert_eq!(map.len(), entries, "all test keys inserted");
            assert!(!peak.incomplete, "allocation probe stayed complete");
            assert_eq!(peak.failed_requests, 0, "no failed test allocations");
            if entries == 0 {
                assert_eq!(peak.live_blocks, 0, "empty map allocates nothing");
            } else {
                assert!(peak.live_blocks > 0, "nonempty map retains nodes");
                assert!(peak.peak_bytes > 0, "nonempty map requests bytes");
            }
            let need = peak
                .peak_bytes
                .max(peak.live_bytes)
                .max(peak.realloc_overlap_bytes);
            assert!(
                bound >= need,
                "bound {bound} covers heap {need} for {entries} entries"
            );
            drop(map);
        }
        fn check_half_removed<K: Ord, V>(
            entries: usize,
            mut key: impl FnMut(u64) -> K,
            mut value: impl FnMut(u64) -> V,
        ) {
            let remaining = entries / 2;
            let full = conservative_pin_tree_bytes::<K, V>(entries)
                .expect("tight bound fits for the test sizes");
            assert_eq!(
                full,
                expected_bytes::<K, V>(entries),
                "tight node count for {entries} entries"
            );
            let rest = conservative_pin_tree_bytes::<K, V>(remaining)
                .expect("tight bound fits for the test sizes");
            assert_eq!(
                rest,
                expected_bytes::<K, V>(remaining),
                "tight node count for {remaining} entries"
            );
            let (map, peak) = crate::test_alloc::requested_peak_during(|| {
                let mut map = std::collections::BTreeMap::new();
                for k in 0..entries as u64 {
                    map.insert(key(k), value(k));
                }
                for k in (0..entries as u64).filter(|k| k % 2 == 0) {
                    map.remove(&key(k));
                }
                map
            });
            assert_eq!(map.len(), remaining, "half the test keys removed");
            assert!(!peak.incomplete, "allocation probe stayed complete");
            assert_eq!(peak.failed_requests, 0, "no failed test allocations");
            assert!(
                full >= peak.peak_bytes.max(peak.realloc_overlap_bytes),
                "full bound {full} covers insertion peak {}",
                peak.peak_bytes.max(peak.realloc_overlap_bytes),
            );
            assert!(
                rest >= peak.live_bytes,
                "remaining bound {rest} covers live {}",
                peak.live_bytes,
            );
            drop(map);
        }
        for entries in [0, 1, 5, 11, 12, 64, 4096] {
            for order in [ascending(entries), descending(entries), xorshifted(entries)] {
                check_cover::<u64, u64>(entries, &order, |k| k, |k| k.wrapping_mul(3));
                check_cover::<u64, ()>(entries, &order, |k| k, |_| ());
                check_cover::<u64, [u64; 16]>(entries, &order, |k| k, |k| [k; 16]);
                check_cover::<[u64; 4], [u64; 4]>(entries, &order, |k| [k, 0, 1, 2], |k| [k; 4]);
            }
            if entries >= 2 {
                check_half_removed::<u64, u64>(entries, |k| k, |k| k);
                check_half_removed::<u64, ()>(entries, |k| k, |_| ());
                check_half_removed::<u64, [u64; 16]>(entries, |k| k, |k| [k; 16]);
                check_half_removed::<[u64; 4], [u64; 4]>(entries, |k| [k, 0, 1, 2], |k| [k; 4]);
            }
        }
        #[repr(align(16))]
        struct OverAligned;
        assert!(
            conservative_pin_tree_bytes::<OverAligned, u64>(1).is_none(),
            "over-aligned keys refuse"
        );
        assert!(
            conservative_pin_tree_bytes::<u64, OverAligned>(1).is_none(),
            "over-aligned values refuse"
        );
        assert!(
            conservative_pin_tree_bytes::<u64, u64>(usize::MAX).is_none(),
            "huge maps refuse instead of wrapping"
        );
    }

    #[test]
    fn conservative_installed_reclaim_releases_session_shared_exports() {
        use crate::semantics_edge::resources::SemanticResourcePool;
        // A Session-held clone of retired exports is released by dropping our
        // share; reclaim completes and the holder keeps its data.
        {
            let (_dir, mut source, _) = conservative_cursor_fixture();
            let pool = SemanticResourcePool::default();
            let reserve = pool.reserver();
            let selection = conservative_selection(
                &pool,
                BTreeSet::from([ProcessViewId(2), ProcessViewId(3)]),
                BTreeSet::new(),
            );
            let id_for = |provider: &str| {
                source
                    .by_id
                    .iter()
                    .find(|(_, entry)| entry.path.contains(provider))
                    .map(|(id, _)| *id)
                    .unwrap()
            };
            let id_r1 = id_for("provider-1");
            let id_r2 = id_for("provider-2");
            source.by_id.get_mut(&id_r1).unwrap().exports = Arc::from(vec![
                ("session-shared-r1-first".repeat(8), 11),
                ("session-shared-r1-second".repeat(8), 22),
            ]);
            source.by_id.get_mut(&id_r2).unwrap().exports =
                Arc::from(vec![("session-shared-r2-only".repeat(16), 33)]);
            let outside_r1 = source.by_id.get(&id_r1).unwrap().exports.clone();
            let outside_r2 = source.by_id.get(&id_r2).unwrap().exports.clone();
            assert_eq!(
                Arc::strong_count(&outside_r1),
                2,
                "old entry plus the Session holder"
            );
            assert_eq!(
                Arc::strong_count(&outside_r2),
                2,
                "old entry plus the Session holder"
            );
            let mut cursor = PinnedConservativeCursor::new();
            finish_conservative_copy(&source, &mut cursor, &selection, &reserve);
            let count = cursor.retired_entry_count().unwrap();
            let mut handoff = RetiredFileHandoff::reserve(count, &reserve).unwrap();
            let mut canonical = source;
            let backing = cursor.install_ready(&mut canonical).unwrap();
            let outcome = drive_pins_installed_reclaim(
                &mut cursor,
                &canonical,
                &selection,
                &mut handoff,
                &reserve,
            );
            assert!(outcome.is_ok(), "shared exports release: {outcome:?}");
            assert_eq!(handoff.len_for_test(), 2, "files hand off, exports do not");
            assert_eq!(Arc::strong_count(&outside_r1), 1);
            assert_eq!(Arc::strong_count(&outside_r2), 1);
            assert_eq!(outside_r1.len(), 2);
            assert!(outside_r1.iter().all(|(text, _)| !text.is_empty()));
            assert!(outside_r1[0].0.starts_with("session-shared-r1-first"));
            assert_eq!(outside_r2.len(), 1);
            assert!(outside_r2[0].0.starts_with("session-shared-r2-only"));
            drop(canonical);
            drop(backing);
            drop(handoff);
        }
        // An unknown Weak still refuses; dropping it lets the exclusive drain
        // finish.
        {
            let (_dir, mut source, _) = conservative_cursor_fixture();
            let pool = SemanticResourcePool::default();
            let reserve = pool.reserver();
            let selection = conservative_selection(
                &pool,
                BTreeSet::from([ProcessViewId(2), ProcessViewId(3)]),
                BTreeSet::new(),
            );
            let id_r1 = source
                .by_id
                .iter()
                .find(|(_, entry)| entry.path.contains("provider-1"))
                .map(|(id, _)| *id)
                .unwrap();
            source.by_id.get_mut(&id_r1).unwrap().exports =
                Arc::from(vec![("weak-guarded-export".repeat(8), 1)]);
            let mut cursor = PinnedConservativeCursor::new();
            finish_conservative_copy(&source, &mut cursor, &selection, &reserve);
            let count = cursor.retired_entry_count().unwrap();
            let mut handoff = RetiredFileHandoff::reserve(count, &reserve).unwrap();
            let mut canonical = source;
            let backing = cursor.install_ready(&mut canonical).unwrap();
            let weak = Arc::downgrade(
                &cursor
                    .installed_output_for_test()
                    .unwrap()
                    .by_id
                    .get(&id_r1)
                    .unwrap()
                    .exports,
            );
            let refused = drive_pins_installed_reclaim(
                &mut cursor,
                &canonical,
                &selection,
                &mut handoff,
                &reserve,
            );
            assert!(matches!(refused, Err(GraphRefusal::Identity)));
            assert_eq!(handoff.len_for_test(), 1);
            assert!(weak.upgrade().is_some(), "refused exports keep their data");
            drop(weak);
            let outcome = drive_pins_installed_reclaim(
                &mut cursor,
                &canonical,
                &selection,
                &mut handoff,
                &reserve,
            );
            assert!(
                outcome.is_ok(),
                "drain finishes after Weak drops: {outcome:?}"
            );
            assert_eq!(handoff.len_for_test(), 2);
            drop(canonical);
            drop(backing);
            drop(handoff);
        }
    }

    #[test]
    fn scanned_installed_reclaim_releases_session_shared_exports() {
        use crate::semantics_edge::resources::SemanticResourcePool;
        // A Session-held clone of a retired module's exports is released by
        // dropping our share; reclaim completes and the holder keeps its data.
        {
            let (_dir, mut source, modules) = conservative_cursor_fixture();
            let id_r = source
                .by_id
                .iter()
                .find(|(_, entry)| entry.path.contains("provider-2"))
                .map(|(id, _)| *id)
                .unwrap();
            source.by_id.get_mut(&id_r).unwrap().exports = Arc::from(vec![
                ("session-shared-module-first".repeat(8), 11),
                ("session-shared-module-second".repeat(16), 22),
                ("session-shared-module-third".repeat(32), 33),
            ]);
            let mut old_pins = source.clone();
            old_pins.reset_derived_claims();
            let (old_modules, _) = bind_scanned_modules(&modules, &mut old_pins);
            drop(old_pins);
            assert!(old_modules.iter().any(|module| module.object == id_r));
            source.by_id.get_mut(&id_r).unwrap().exports =
                Arc::from(vec![("live-successor-export".into(), 44)]);
            let outside = old_modules
                .iter()
                .find(|module| module.object == id_r)
                .unwrap()
                .exports
                .clone();
            assert_eq!(
                Arc::strong_count(&outside),
                2,
                "old module plus the Session holder"
            );
            let pool = SemanticResourcePool::default();
            let reserve = pool.reserver();
            let selection =
                conservative_selection(&pool, BTreeSet::from([ProcessViewId(3)]), BTreeSet::new());
            let mut pins = PinnedConservativeCursor::new();
            finish_conservative_copy(&source, &mut pins, &selection, &reserve);
            assert!(!pins.pinned().unwrap().by_id.contains_key(&id_r));
            let rows: Vec<ScannedModule> = modules
                .iter()
                .filter(|module| module.view != ProcessViewId(3))
                .cloned()
                .collect();
            assert_eq!(rows.len(), 3);
            let (mut input, _) = retained_rebind_inputs(&pool, &rows, false);
            let mut rebind = ScannedRebindCursor::new();
            finish_scanned_rebind(&mut pins, &mut input, &mut rebind, &reserve);
            assert!(input.is_none());
            let count = pins.retired_entry_count();
            assert_eq!(count, Some(1), "one retired claim bounds the handoff");
            let mut handoff = RetiredFileHandoff::reserve(count.unwrap(), &reserve).unwrap();
            let mut canonical = source;
            let mut canonical_modules = old_modules;
            let pins_backing = pins.install_ready(&mut canonical).unwrap();
            let modules_backing = rebind.install_ready(&mut canonical_modules).unwrap();
            let outcome = drive_rebind_installed_reclaim(
                &mut rebind,
                &mut pins,
                &canonical,
                &mut handoff,
                &reserve,
            );
            assert!(
                outcome.is_ok(),
                "shared module exports release: {outcome:?}"
            );
            assert_eq!(
                handoff.len_for_test(),
                0,
                "module exports never enter the file handoff"
            );
            assert_eq!(pins.installed_state_for_test(), (true, true));
            assert_eq!(Arc::strong_count(&outside), 1);
            assert_eq!(outside.len(), 3);
            assert!(outside.iter().all(|(text, _)| !text.is_empty()));
            assert!(outside[0].0.starts_with("session-shared-module-first"));
            let outcome = drive_pins_installed_reclaim(
                &mut pins,
                &canonical,
                &selection,
                &mut handoff,
                &reserve,
            );
            assert!(outcome.is_ok(), "retired file still hands off: {outcome:?}");
            assert_eq!(handoff.len_for_test(), 1);
            drop(canonical);
            drop(canonical_modules);
            drop(pins_backing);
            drop(modules_backing);
            drop(handoff);
        }
        // An unknown Weak still refuses; dropping it lets the exclusive drain
        // finish.
        {
            let (_dir, mut source, modules) = conservative_cursor_fixture();
            let id_r = source
                .by_id
                .iter()
                .find(|(_, entry)| entry.path.contains("provider-2"))
                .map(|(id, _)| *id)
                .unwrap();
            source.by_id.get_mut(&id_r).unwrap().exports = Arc::from(vec![
                ("weak-guarded-module-first".repeat(8), 11),
                ("weak-guarded-module-second".repeat(8), 22),
            ]);
            let mut old_pins = source.clone();
            old_pins.reset_derived_claims();
            let (old_modules, _) = bind_scanned_modules(&modules, &mut old_pins);
            drop(old_pins);
            source.by_id.get_mut(&id_r).unwrap().exports =
                Arc::from(vec![("live-successor-export".into(), 44)]);
            let probe = old_modules
                .iter()
                .find(|module| module.object == id_r)
                .unwrap()
                .exports
                .clone();
            assert_eq!(Arc::strong_count(&probe), 2);
            drop(probe);
            let weak = Arc::downgrade(
                &old_modules
                    .iter()
                    .find(|module| module.object == id_r)
                    .unwrap()
                    .exports,
            );
            let pool = SemanticResourcePool::default();
            let reserve = pool.reserver();
            let selection =
                conservative_selection(&pool, BTreeSet::from([ProcessViewId(3)]), BTreeSet::new());
            let mut pins = PinnedConservativeCursor::new();
            finish_conservative_copy(&source, &mut pins, &selection, &reserve);
            let rows: Vec<ScannedModule> = modules
                .iter()
                .filter(|module| module.view != ProcessViewId(3))
                .cloned()
                .collect();
            let (mut input, _) = retained_rebind_inputs(&pool, &rows, false);
            let mut rebind = ScannedRebindCursor::new();
            finish_scanned_rebind(&mut pins, &mut input, &mut rebind, &reserve);
            let count = pins.retired_entry_count().unwrap();
            let mut handoff = RetiredFileHandoff::reserve(count, &reserve).unwrap();
            let mut canonical = source;
            let mut canonical_modules = old_modules;
            let pins_backing = pins.install_ready(&mut canonical).unwrap();
            let modules_backing = rebind.install_ready(&mut canonical_modules).unwrap();
            let refused = drive_rebind_installed_reclaim(
                &mut rebind,
                &mut pins,
                &canonical,
                &mut handoff,
                &reserve,
            );
            assert!(matches!(refused, Err(GraphRefusal::Identity)));
            assert_eq!(handoff.len_for_test(), 0);
            assert!(weak.upgrade().is_some(), "refused exports keep their data");
            drop(weak);
            let outcome = drive_rebind_installed_reclaim(
                &mut rebind,
                &mut pins,
                &canonical,
                &mut handoff,
                &reserve,
            );
            assert!(
                outcome.is_ok(),
                "drain finishes after Weak drops: {outcome:?}"
            );
            assert_eq!(handoff.len_for_test(), 0);
            let outcome = drive_pins_installed_reclaim(
                &mut pins,
                &canonical,
                &selection,
                &mut handoff,
                &reserve,
            );
            assert!(outcome.is_ok(), "retired file still hands off: {outcome:?}");
            assert_eq!(handoff.len_for_test(), 1);
            drop(canonical);
            drop(canonical_modules);
            drop(pins_backing);
            drop(modules_backing);
            drop(handoff);
        }
    }

    #[test]
    fn test_fixture_record_scan_ownership_adds_product_shape_ownership() {
        let shared_file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut &shared_file, &[0x7fu8; 4096]).unwrap();
        let shared_path = shared_file.path().to_path_buf();
        let shared_path_text = shared_path.to_str().unwrap().to_string();
        let keys: Vec<ObjectKey> = (0..2u64)
            .map(|index| ObjectKey {
                device: Device {
                    major: 8,
                    minor: index,
                },
                inode: 1000 + index,
            })
            .collect();
        let mut pins = PinnedObjects::empty();
        for (index, key) in keys.iter().enumerate() {
            let absorbed = pins.absorb(test_fixture::real_scan_pin(
                &shared_path,
                Some(*key),
                index as u64,
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            ));
            assert!(absorbed.is_empty(), "distinct keys absorb cleanly");
        }
        assert!(pins.ownership.is_empty(), "absorb bypasses scan ownership");
        assert!(
            pins.raw_ownership.is_empty(),
            "absorb bypasses raw ownership"
        );
        for (index, key) in keys.iter().enumerate() {
            test_fixture::record_scan_ownership(
                &mut pins,
                ProcessViewId(index as u32),
                *key,
                &shared_path_text,
            );
        }
        assert_eq!(pins.ownership.len(), 2);
        assert_eq!(pins.raw_ownership.len(), 2);
        for (index, key) in keys.iter().enumerate() {
            let view = ProcessViewId(index as u32);
            let claims = pins.ownership.get(&view).unwrap();
            assert_eq!(claims.pins.len(), 1);
            let raws = pins.raw_ownership.get(&view).unwrap();
            assert_eq!(raws.len(), 1);
            let raw = raws.iter().next().unwrap();
            assert_eq!(raw.key, *key);
            assert_eq!(pins.raw_to_id.get(raw).copied(), Some(claims.pins[0]));
        }
    }
}
