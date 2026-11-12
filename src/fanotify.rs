//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Kernel file-open learning (learn-file lane, C2-FD): a fanotify drain
//! watches every open on every real filesystem, proves at most once per
//! file whether the opened bytes export a PKCS#11 entry point, and hands
//! provider-positive files — already held open, so the exact bytes survive
//! the loading process — to the engine for pin/prove/attach through the
//! existing pre-arm path. No BPF changes, no alive window, no vendor or
//! path lists. Event fds, pidfds and readlink strings of files that fail
//! the provider test never leave this module.

use std::collections::{BTreeSet, HashMap};
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender};

/// Per-capture cap on staged learned files (spike C2 plan): beyond it the
/// engine refuses loudly with the aggregate cap gap, never silently.
pub(crate) const LEARNED_FILES_PER_CAPTURE_CAP: usize = 32;

/// Bound on the drain's per-file decision cache: negatives past the cap are
/// forgotten (a re-check is just work), staged providers never are.
pub(crate) const LEARN_CACHE_CAP: usize = 8192;

/// Channel depth between the drain thread and the engine: the drain blocks
/// past it, so overload degrades to kernel queue overflow (a named gap),
/// never to silent loss.
const LEARN_CHANNEL_DEPTH: usize = 64;

/// How many open bytes prove (or refuse) ELF identity before the bounded
/// export parse runs.
const ELF_MAGIC_LEN: usize = 64;

/// `fanotify_event_metadata` is 24 bytes; libc exposes the struct but no
/// length constant, so the parser uses its size directly.
const FANOTIFY_META_LEN: usize = std::mem::size_of::<libc::fanotify_event_metadata>();
/// `FANOTIFY_METADATA_VERSION` (libc exposes no constant): every record
/// the parser accepts carries it.
const FANOTIFY_METADATA_VERSION: u8 = 3;

/// One provider file the drain proved on held bytes: the open fd pins the
/// exact inode across process death, rename and delete, so the engine's
/// pin opens `/proc/self/fd/N` and never re-resolves a pathname.
pub(crate) struct LearnedCandidate {
    /// Held `O_RDONLY` event fd. Pins the file; the pin worker opens
    /// `/proc/self/fd/N` while this is alive.
    pub(crate) file: std::fs::File,
    /// `st_dev`/`st_ino` of the held fd: the kernel identity of the file
    /// that was actually opened. Display only travels beside it.
    pub(crate) dev: u64,
    pub(crate) ino: u64,
    /// Readlink of the event fd at first sight: display spelling only,
    /// never opened, never identity.
    pub(crate) display_path: String,
    /// `/proc/<loader>/exe` at first sight, or the finite reason below.
    pub(crate) loader_exe: Option<String>,
    pub(crate) loader_unknown_reason: Option<&'static str>,
}

/// Drain-to-engine messages. `Load` tallies post-send opens so the staged
/// note counts the missed runs; it carries no fd and no path.
pub(crate) enum LearnMsg {
    Candidate(LearnedCandidate),
    Load {
        dev: u64,
        ino: u64,
        pid: u32,
    },
    QueueOverflow,
    /// A mark pass left a visible filesystem uncovered (for example a
    /// newly mounted filesystem after the post-setup capability shed
    /// took `CAP_SYS_ADMIN`): learning is degraded there, filed once
    /// as a named gap while the capture continues (data-always).
    Unavailable,
}

/// Why the drain could not start: the capture keeps today's gaps (and a
/// `-v` line), never a fatal.
#[derive(Debug)]
pub(crate) struct LearnAbsent {
    pub(crate) reason: String,
}

/// Finite reason when the loading program's exe link could not be read
/// (it usually already exited).
pub(crate) const LOADER_EXE_UNREADABLE_REASON: &str = "loader exe link unreadable";

/// Operator off switch for file learning: exactly
/// `P11SCOPE_DISABLE_FILE_LEARNING=1` disables the fanotify drain (the
/// capture keeps ordinary discovery and files the disabled-learning
/// gap). Capture-visible in `evidence.p11scope_env`.
pub(crate) const DISABLE_FILE_LEARNING_ENV: &str = "P11SCOPE_DISABLE_FILE_LEARNING";

/// Whether an off-switch value disables learning: exactly `"1"`, like
/// the other `P11SCOPE_*` switches. Pure so tests never mutate the
/// process environment.
pub(crate) fn file_learning_disabled(value: Option<&str>) -> bool {
    value == Some("1")
}

/// The off switch as set in this process's environment.
pub(crate) fn file_learning_disabled_from_env() -> bool {
    file_learning_disabled(std::env::var(DISABLE_FILE_LEARNING_ENV).ok().as_deref())
}

/// Whether two mount-namespace link texts prove different namespaces:
/// both must have read and differ. An unreadable link proves nothing
/// (an unprivileged observer cannot read `/proc/1/ns/mnt`), so it
/// never files a false scope gap.
pub(crate) fn mount_namespaces_differ(self_ns: Option<&str>, init_ns: Option<&str>) -> bool {
    matches!((self_ns, init_ns), (Some(a), Some(b)) if a != b)
}

/// Whether the observer's mount namespace differs from pid 1's (for
/// example a `--pid=host` container, or the host watching rootless
/// podman): filesystem marks are placed from `/proc/self/mountinfo`
/// only, so filesystems outside this namespace are never marked and
/// their providers are never learned. The caller files the named
/// mount-namespace learning gap; learning still runs in-namespace.
pub(crate) fn observer_mount_namespace_differs_from_init() -> bool {
    let read = |path: &str| {
        std::fs::read_link(path)
            .ok()
            .map(|target| target.to_string_lossy().into_owned())
    };
    mount_namespaces_differ(
        read("/proc/self/ns/mnt").as_deref(),
        read("/proc/1/ns/mnt").as_deref(),
    )
}

/// Kernel identity of the opened file behind a held fd.
#[cfg(test)]
pub(crate) fn file_identity(file: &std::fs::File) -> Result<(u64, u64), String> {
    use std::os::unix::fs::MetadataExt;
    let meta = file
        .metadata()
        .map_err(|error| format!("metadata failed: {error}"))?;
    Ok((meta.dev(), meta.ino()))
}

/// Check-once generation key: an in-place rewrite is a new generation and
/// is re-checked, so a file first seen mid-write is not negative forever.
/// Mirrors the pin bracket (`ino`, `size`, `ctime`) plus the device.
pub(crate) type FileGeneration = (u64, u64, u64, i64, i64);

/// `(st_dev, st_ino, size, ctime seconds, ctime nanoseconds)` of a held fd.
pub(crate) fn file_generation(file: &std::fs::File) -> Result<FileGeneration, String> {
    use std::os::unix::fs::MetadataExt;
    let meta = file
        .metadata()
        .map_err(|error| format!("metadata failed: {error}"))?;
    Ok((
        meta.dev(),
        meta.ino(),
        meta.len(),
        meta.ctime(),
        meta.ctime_nsec(),
    ))
}

/// The one provider test, over held bytes only: ELF magic, then the shared
/// bounded export parse, then the entry-point predicate below. No vendor
/// or path list, no execution.
///
/// Returns `Ok(false)` only for certain negatives (not a regular file,
/// not ELF, no entry-point export). I/O failures return `Err`: the
/// caller must NOT cache them (a transient stall retries on the next
/// open). Never blocks: the fd is non-blocking and every read is
/// bounded, so a fifo or a stalled pseudo-file cannot wedge the drain.
pub(crate) fn check_elf_provider(file: &std::fs::File) -> Result<bool, String> {
    use std::os::unix::fs::FileExt;
    let file_type = file
        .metadata()
        .map_err(|error| format!("metadata failed: {error}"))?
        .file_type();
    if !file_type.is_file() {
        return Ok(false);
    }
    // SAFETY: fcntl on our own event fd; preserves existing flags.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags >= 0 {
        unsafe {
            libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
    }
    let mut magic = [0u8; ELF_MAGIC_LEN];
    let read = file
        .read_at(&mut magic, 0)
        .map_err(|error| format!("magic read failed: {error}"))?;
    if read < 4 || magic[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Ok(false);
    }
    if !elf_may_export_entry_points(file)? {
        return Ok(false);
    }
    let inspected = p11scope_manifest::identity::inspect_file_with_reader_exporting(
        file,
        |file, bytes, offset| file.read_at(bytes, offset),
        &crate::discovery::scan::standard_function_names(),
    )
    .map_err(|error| format!("identify failed: {error}"))?;
    Ok(exports_entry_point(&inspected.exports))
}

/// Whether an export list proves a PKCS#11 provider: an entry-point
/// name, exact or version-suffixed (`C_GetFunctionList@@NSS_3.4`).
/// No vendor or path list is consulted.
pub(crate) fn exports_entry_point(exports: &[(String, u64)]) -> bool {
    const ENTRY_POINTS: [&str; 3] = ["C_GetFunctionList", "C_GetInterface", "C_GetInterfaceList"];
    exports.iter().any(|(name, _)| {
        ENTRY_POINTS.iter().any(|entry| {
            name == entry
                || name
                    .strip_prefix(entry)
                    .is_some_and(|rest| rest.starts_with('@'))
        })
    })
}

/// Cheap sound pre-test before the whole-file parse: walks the ELF
/// header, program headers and `PT_DYNAMIC` (a few bounded preads) to
/// find the dynamic string table, and searches it for a PKCS#11
/// entry-point name. `Ok(false)` only when the table is found and holds
/// no name (an export needs its name there, so none can exist); every
/// parse doubt or I/O failure returns `Ok(true)`/`Err` and falls
/// through to the full authoritative parse, never a false negative.
fn elf_may_export_entry_points(file: &std::fs::File) -> Result<bool, String> {
    use std::os::unix::fs::FileExt;
    const ENTRY_NAMES: [&[u8]; 3] = [
        b"C_GetFunctionList",
        b"C_GetInterface",
        b"C_GetInterfaceList",
    ];
    const EHDR_64: usize = 64;
    const PHDR_64: usize = 56;
    const DYNAMIC_ENTRY: usize = 16;
    const PT_LOAD: u32 = 1;
    const PT_DYNAMIC: u32 = 2;
    const DT_STRTAB: i64 = 5;
    const DT_STRSZ: i64 = 10;
    const MAX_PHNUM: usize = 64;
    const MAX_DYNAMIC: usize = 64;
    const MAX_STRTAB: usize = 1024 * 1024;
    let mut ehdr = [0u8; EHDR_64];
    if file
        .read_at(&mut ehdr, 0)
        .map_err(|error| format!("ehdr: {error}"))?
        < EHDR_64
    {
        return Ok(true);
    }
    if ehdr[0..4] != [0x7f, b'E', b'L', b'F'] || ehdr[4] != 2 || ehdr[5] != 1 {
        return Ok(true);
    }
    let word =
        |at: usize| -> u64 { u64::from_le_bytes(ehdr[at..at + 8].try_into().unwrap_or([0; 8])) };
    let half = |at: usize| -> usize {
        u16::from_le_bytes(ehdr[at..at + 2].try_into().unwrap_or([0; 2])) as usize
    };
    // Relocatable objects and core dumps can never be loaded as a
    // provider: certain negatives. Without this arm every `.o` a build
    // opens (thousands per minute on a busy host) fell through to the
    // full inspect and the single drain thread fell minutes behind.
    let e_type = half(0x10);
    if e_type == 1 || e_type == 4 {
        return Ok(false);
    }
    let (phoff, phentsize, phnum) = (word(0x20), half(0x36), half(0x38));
    if phentsize < PHDR_64 || phnum == 0 || phnum > MAX_PHNUM {
        return Ok(true);
    }
    // One bounded read for all program headers (the drain runs this on
    // every distinct ELF a busy system opens; per-header reads cost
    // more than the parse).
    let mut phdrs = vec![0u8; phnum * phentsize];
    if file
        .read_at(&mut phdrs, phoff)
        .map_err(|error| format!("phdr: {error}"))?
        < phdrs.len()
    {
        return Ok(true);
    }
    let mut segments = Vec::new();
    let mut dynamic = None;
    for index in 0..phnum {
        let phdr = &phdrs[index * phentsize..index * phentsize + PHDR_64];
        let field = |at: usize| -> u64 {
            u64::from_le_bytes(phdr[at..at + 8].try_into().unwrap_or([0; 8]))
        };
        let tag = u32::from_le_bytes(phdr[0..4].try_into().unwrap_or([0; 4]));
        if tag == PT_LOAD {
            segments.push((field(0x10), field(0x08), field(0x20)));
        } else if tag == PT_DYNAMIC && dynamic.is_none() {
            dynamic = Some((field(0x08), field(0x20)));
        }
    }
    let Some((dyn_offset, dyn_size)) = dynamic else {
        return Ok(false);
    };
    if dyn_size as usize > MAX_DYNAMIC * DYNAMIC_ENTRY {
        return Ok(true);
    }
    let mut strtab = None;
    let mut strsz = None;
    // One bounded read for the whole dynamic array, like the phdrs.
    let mut dynamics = vec![0u8; dyn_size as usize];
    if file
        .read_at(&mut dynamics, dyn_offset)
        .map_err(|error| format!("dynamic: {error}"))?
        < dynamics.len()
    {
        return Ok(true);
    }
    for index in 0..MAX_DYNAMIC {
        let Some(entry) = dynamics.get(index * DYNAMIC_ENTRY..(index + 1) * DYNAMIC_ENTRY) else {
            break;
        };
        let tag = i64::from_le_bytes(entry[0..8].try_into().unwrap_or([0; 8]));
        let value = u64::from_le_bytes(entry[8..16].try_into().unwrap_or([0; 8]));
        if tag == 0 {
            break;
        }
        if tag == DT_STRTAB {
            strtab = Some(value);
        } else if tag == DT_STRSZ {
            strsz = Some(value);
        }
    }
    let (Some(strtab), Some(strsz)) = (strtab, strsz) else {
        return Ok(false);
    };
    if strsz == 0 || strsz as usize > MAX_STRTAB {
        return Ok(true);
    }
    let mut strtab_offset = None;
    for (vaddr, offset, filesz) in &segments {
        if strtab >= *vaddr && strtab.saturating_sub(*vaddr) < *filesz {
            strtab_offset = Some(offset.saturating_add(strtab - vaddr));
            break;
        }
    }
    let Some(strtab_offset) = strtab_offset else {
        return Ok(true);
    };
    let mut names = vec![0u8; strsz as usize];
    if file
        .read_at(&mut names, strtab_offset)
        .map_err(|error| format!("strtab: {error}"))?
        != strsz as usize
    {
        return Ok(true);
    }
    // Suffix-shared string tables store `C_GetFunctionList` inside a
    // longer token (`PrefixC_GetFunctionList`): search at any offset,
    // requiring only the trailing delimiter (NUL or the version `@`).
    // A longer name that merely contains an entry name mid-word still
    // passes this pre-test and is refused by the full parse; the
    // pre-test must never refuse a real provider. One pass over the
    // shared `C_Get` prefix: the drain runs this on every distinct
    // ELF a busy system opens, so per-name rescans are too slow.
    let mut start = 0;
    while start + 5 <= names.len() {
        let Some(relative) = names[start..]
            .windows(5)
            .position(|window| window == b"C_Get")
        else {
            break;
        };
        let at = start + relative;
        for entry in ENTRY_NAMES {
            if names[at..].starts_with(entry) {
                match names.get(at + entry.len()) {
                    None | Some(0) | Some(b'@') => return Ok(true),
                    _ => {}
                }
            }
        }
        start = at + 1;
    }
    Ok(false)
}

/// Display spelling for a held event fd: its readlink at this instant.
pub(crate) fn display_path_for(file: &std::fs::File) -> Option<String> {
    std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

/// Names a program from a bare pid. On its own this binds nothing:
/// production naming goes through `loader_exe_for_pidfd`, which
/// brackets this read with pidfd liveness so a recycled pid is never
/// named. A dead loader resolves to the one finite reason.
pub(crate) fn resolve_loader_exe(pid: u32) -> (Option<String>, Option<&'static str>) {
    if pid == 0 {
        return (None, Some(LOADER_EXE_UNREADABLE_REASON));
    }
    match std::fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(path) => (Some(path.to_string_lossy().into_owned()), None),
        Err(_) => (None, Some(LOADER_EXE_UNREADABLE_REASON)),
    }
}

/// Per-generation drain decision: each file generation is proved at most
/// once. Keys identity only; paths never enter the cache.
#[derive(Debug, Default)]
pub(crate) struct LearnCache {
    decided: HashMap<FileGeneration, bool>,
}

impl LearnCache {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.decided.len()
    }

    /// Whether this generation still needs its one check.
    pub(crate) fn needs_check(&self, generation: FileGeneration) -> bool {
        !self.decided.contains_key(&generation)
    }

    pub(crate) fn note_decided(&mut self, generation: FileGeneration, provider: bool) {
        self.decided.insert(generation, provider);
        if self.decided.len() > LEARN_CACHE_CAP {
            self.decided.retain(|_, proved| *proved);
            // A provider storm must not grow this without bound either:
            // forgetting a proved file only re-sends its candidate,
            // which the engine dedupes by pinned identity.
            if self.decided.len() > LEARN_CACHE_CAP {
                self.decided.clear();
                self.decided.insert(generation, provider);
            }
        }
    }

    pub(crate) fn decided_provider(&self, generation: FileGeneration) -> Option<bool> {
        self.decided.get(&generation).copied()
    }
}

/// Pseudo filesystems that never hold providers and are never marked.
/// Anything else is attempted; per-mount failures (overlayfs/9p
/// `EOPNOTSUPP`, racing unmounts) are tolerated, never fatal.
const PSEUDO_FS: &[&str] = &[
    "proc",
    "sysfs",
    "cgroup",
    "cgroup2",
    "debugfs",
    "tracefs",
    "bpf",
    "securityfs",
    "configfs",
    "fusectl",
    "selinuxfs",
    "nsfs",
    "binfmt_misc",
    "mqueue",
    "devpts",
    "sockfs",
    "pipefs",
    "anon_inodefs",
];

/// One mount's kernel identity: its mount id plus its filesystem
/// device (`major:minor` from mountinfo). Mark coverage keys on
/// this, never on the mount-point path: a filesystem mounted at a
/// path an earlier mount occupied is a different identity, and the
/// earlier mount's mark died with its unmounted superblock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct MountIdentity {
    mount_id: u64,
    dev_major: u32,
    dev_minor: u32,
}

/// One visible mount a mark pass must cover: the point is only the
/// locator handed to `fanotify_mark`; the identity decides coverage.
/// `None` when the mountinfo identity fields do not parse — such a
/// mount can be marked but its coverage cannot be retained, so a
/// failed mark counts it uncovered (fail-closed).
pub(crate) struct MountToMark {
    point: std::path::PathBuf,
    identity: Option<MountIdentity>,
}

/// Mounts to mark, parsed from `/proc/self/mountinfo` text: field 1
/// is the mount id, field 3 the filesystem device, field 5 the mount
/// point, and the field after `" - "` is the fstype. Malformed lines
/// are skipped; escapes (`\040` etc.) are decoded. Paths stay
/// byte-exact (`PathBuf`): a lossy string could miss a mark. A point
/// mounted over keeps the last (topmost) entry, which is where the
/// path resolves.
pub(crate) fn mounts_for_marks(mountinfo: &str) -> Vec<MountToMark> {
    let mut mounts: Vec<MountToMark> = Vec::new();
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        let Some(sep) = fields.iter().position(|field| *field == "-") else {
            continue;
        };
        if fields.len() < 5 || fields.len() <= sep + 1 {
            continue;
        }
        if PSEUDO_FS.contains(&fields[sep + 1]) {
            continue;
        }
        let point = unescape_mountinfo(fields[4]);
        if point.as_os_str().is_empty() {
            continue;
        }
        let identity = parse_mount_identity(fields[0], fields[2]);
        if let Some(existing) = mounts.iter_mut().find(|mount| mount.point == point) {
            existing.identity = identity;
            continue;
        }
        mounts.push(MountToMark { point, identity });
    }
    mounts
}

/// Parses one mountinfo identity pair (`mount id`, `major:minor`).
fn parse_mount_identity(mount_id: &str, dev: &str) -> Option<MountIdentity> {
    let (major, minor) = dev.split_once(':')?;
    Some(MountIdentity {
        mount_id: mount_id.parse().ok()?,
        dev_major: major.parse().ok()?,
        dev_minor: minor.parse().ok()?,
    })
}

/// Decodes mountinfo octal escapes in a mount-point field, byte-exact.
fn unescape_mountinfo(field: &str) -> std::path::PathBuf {
    use std::os::unix::ffi::OsStringExt;
    let mut out = Vec::with_capacity(field.len());
    let bytes = field.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && index + 3 < bytes.len()
            && bytes[index + 1].is_ascii_digit()
            && bytes[index + 2].is_ascii_digit()
            && bytes[index + 3].is_ascii_digit()
        {
            let value = (bytes[index + 1] - b'0') * 64
                + (bytes[index + 2] - b'0') * 8
                + (bytes[index + 3] - b'0');
            out.push(value);
            index += 4;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    std::path::PathBuf::from(std::ffi::OsString::from_vec(out))
}

/// One parsed fanotify record: the event fd, the reuse-immune pidfd info,
/// and whether the queue overflowed. The metadata pid is carried for the
/// self-skip only (our own pid cannot be reused while we live); every
/// attribution uses the pidfd-derived pid.
pub(crate) struct ParsedFanotifyEvent {
    pub fd: i32,
    pub pid: i32,
    pub pidfd: Option<i32>,
    pub overflow: bool,
    /// Total record length: the drain advances by this many bytes.
    pub total_len: usize,
}

/// Parses one record at the buffer start. Pure over bytes: fds are parsed,
/// never touched.
pub(crate) fn parse_fanotify_event(buf: &[u8]) -> Result<ParsedFanotifyEvent, String> {
    if buf.len() < FANOTIFY_META_LEN {
        return Err("short fanotify buffer".to_string());
    }
    let event_len = u32::from_ne_bytes(
        buf[0..4]
            .try_into()
            .map_err(|_| "short length".to_string())?,
    ) as usize;
    if event_len < FANOTIFY_META_LEN || buf.len() < event_len {
        return Err("short fanotify event".to_string());
    }
    if buf[4] != FANOTIFY_METADATA_VERSION {
        return Err("unknown fanotify version".to_string());
    }
    let mask = u64::from_ne_bytes(
        buf[8..16]
            .try_into()
            .map_err(|_| "short mask".to_string())?,
    );
    let fd = i32::from_ne_bytes(buf[16..20].try_into().map_err(|_| "short fd".to_string())?);
    let pid = i32::from_ne_bytes(
        buf[20..24]
            .try_into()
            .map_err(|_| "short pid".to_string())?,
    );
    if mask & libc::FAN_Q_OVERFLOW != 0 {
        return Ok(ParsedFanotifyEvent {
            fd,
            pid,
            pidfd: None,
            overflow: true,
            total_len: event_len,
        });
    }
    let mut pidfd = None;
    let mut offset = FANOTIFY_META_LEN;
    while offset + 4 <= event_len {
        let info_type = buf[offset];
        let info_len = u16::from_ne_bytes(
            buf[offset + 2..offset + 4]
                .try_into()
                .map_err(|_| "short info".to_string())?,
        ) as usize;
        if info_len < 4 || offset + info_len > event_len {
            break;
        }
        if info_type == libc::FAN_EVENT_INFO_TYPE_PIDFD && info_len >= 8 {
            pidfd = Some(i32::from_ne_bytes(
                buf[offset + 4..offset + 8]
                    .try_into()
                    .map_err(|_| "short pidfd".to_string())?,
            ));
        }
        offset += info_len;
    }
    Ok(ParsedFanotifyEvent {
        fd,
        pid,
        pidfd,
        overflow: false,
        total_len: event_len,
    })
}

/// Best-effort close of every kernel-installed fd in the unread tail
/// of an already-read buffer (records at `offset..len`): closing the
/// fanotify group does not close fds the kernel already returned, so
/// an early drain exit would otherwise leak the tail's event fds and
/// pidfds. Pure length-field walking; a malformed length stops it.
fn close_unread_tail(buf: &[u8], mut offset: usize, len: usize) {
    while offset + FANOTIFY_META_LEN <= len {
        let event_len =
            u32::from_ne_bytes(buf[offset..offset + 4].try_into().unwrap_or([0; 4])) as usize;
        if event_len < FANOTIFY_META_LEN || offset + event_len > len {
            break;
        }
        // SAFETY: close(2) on kernel-returned fds parsed from the
        // record; negative values are not fds. Each record is walked
        // once, so no fd is closed twice.
        let fd = i32::from_ne_bytes(buf[offset + 16..offset + 20].try_into().unwrap_or([0; 4]));
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
        if let Ok(event) = parse_fanotify_event(&buf[offset..offset + event_len])
            && let Some(pidfd) = event.pidfd
            && pidfd >= 0
        {
            unsafe { libc::close(pidfd) };
        }
        offset += event_len;
    }
}

/// Sets `FD_CLOEXEC` explicitly on a kernel-handed fd: the group is
/// created with `FAN_CLOEXEC`, but event and pid fds must not rely on
/// propagation through the observer's own `Command::spawn`s (the
/// discover helper) on every supported kernel.
fn set_cloexec(fd: std::os::unix::io::RawFd) {
    // SAFETY: fcntl on a live owned fd; failure only loses the flag.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags >= 0 {
            libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
        }
    }
}

/// Whether the task a pidfd pins has exited: a pidfd becomes readable
/// exactly when its task terminates.
fn pidfd_exited(pidfd: &OwnedFd) -> bool {
    let mut polled = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: libc poll on one valid fd with a zero timeout.
    let ready = unsafe { libc::poll(&mut polled, 1, 0) };
    ready > 0 && polled.revents & libc::POLLIN != 0
}

/// Names the loading program through a live pidfd, bracketed: the pid
/// comes from the pidfd's fdinfo, the exe link is read only while the
/// pinned task provably still lives, and both are re-checked after
/// the read, so an exited-and-recycled pid can never be named. The
/// read happens at event receipt, before the ELF proof. A loader
/// that already exited — or exec'd a different program between the
/// open and this read, which no pidfd can exclude — resolves to the
/// finite unknown or the current image; callers and docs state the
/// field as the still-live loader's program at learn time.
pub(crate) fn loader_exe_for_pidfd(pidfd: &OwnedFd) -> (Option<String>, Option<&'static str>) {
    let unknown = (None, Some(LOADER_EXE_UNREADABLE_REASON));
    if pidfd_exited(pidfd) {
        return unknown;
    }
    let Some(pid) = pid_of_pidfd(pidfd) else {
        return unknown;
    };
    let (exe, _) = resolve_loader_exe(pid);
    let Some(exe) = exe else {
        return unknown;
    };
    if pidfd_exited(pidfd) || pid_of_pidfd(pidfd) != Some(pid) {
        return unknown;
    }
    (Some(exe), None)
}

/// The drain thread handle, owned by the engine. Drop signals shutdown and
/// joins (the poll timeout bounds the wait).
pub(crate) struct FileLearner {
    state: Arc<LearnShutdownState>,
    thread: Option<std::thread::JoinHandle<()>>,
    /// Group + sender + startup mark coverage held between arming
    /// and `begin_drain`: the reader thread spawns post-shed so it
    /// never retains the transient startup `CAP_SYS_ADMIN`
    /// (capabilities are per-thread). `None` once the drain runs.
    /// The bool records that the startup pass left a visible
    /// filesystem uncovered, which the drain files as the finite
    /// unavailable-learning gap as soon as it runs.
    pending: Option<(OwnedFd, SyncSender<LearnMsg>, BTreeSet<MountIdentity>, bool)>,
}

impl FileLearner {
    /// Opens the fanotify group and marks every real filesystem
    /// (both need the startup `CAP_SYS_ADMIN` grant), but does not
    /// spawn the reader: call `begin_drain` after the post-setup
    /// capability shed. Without the grant (or fanotify at all) this
    /// returns `LearnAbsent` and the capture keeps today's gaps,
    /// never a fatal.
    pub(crate) fn start() -> Result<(Self, Receiver<LearnMsg>), LearnAbsent> {
        // SAFETY: libc call with flag constants only; the return is
        // checked before any use.
        let fd = unsafe {
            libc::fanotify_init(
                // Finite queue and marks on purpose: overload must
                // surface as FAN_Q_OVERFLOW (a named gap), never as
                // unbounded kernel memory behind a stalled drain.
                libc::FAN_CLASS_NOTIF
                    | libc::FAN_CLOEXEC
                    | libc::FAN_NONBLOCK
                    | libc::FAN_REPORT_PIDFD,
                libc::O_RDONLY as u32 | libc::O_LARGEFILE as u32,
            )
        };
        if fd < 0 {
            return Err(LearnAbsent {
                reason: format!("fanotify_init failed: {}", std::io::Error::last_os_error()),
            });
        }
        // SAFETY: fanotify_init returned an owned fd.
        let group = unsafe { OwnedFd::from_raw_fd(fd) };
        let (covered, uncovered) = mark_visible_filesystems(&group, &BTreeSet::new());
        // An identity-less fallback mount that marked successfully
        // leaves the retained set empty with nothing uncovered: that
        // is still a working learner, re-decided at the next pass.
        if covered.is_empty() && uncovered > 0 {
            return Err(LearnAbsent {
                reason: format!("no filesystem could be marked ({uncovered} skipped)"),
            });
        }
        if crate::run::capture_diagnostics_on() {
            eprintln!(
                "p11scope: file learning active: {} filesystems marked ({uncovered} skipped)",
                covered.len()
            );
        }
        let (tx, rx) = std::sync::mpsc::sync_channel(LEARN_CHANNEL_DEPTH);
        let state = Arc::new(LearnShutdownState::default());
        Ok((
            Self {
                state,
                thread: None,
                pending: Some((group, tx, covered, uncovered > 0)),
            },
            rx,
        ))
    }

    /// Spawns the reader thread with the caller's current capability
    /// sets (post-shed). Idempotent. Re-marking from the drain may
    /// fail without `CAP_SYS_ADMIN`; retained initial marks keep
    /// delivering, but a visible filesystem that was never covered
    /// files the finite unavailable-learning gap (data-always: the
    /// capture continues and says so), whatever traffic older
    /// filesystems produce.
    pub(crate) fn begin_drain(&mut self) -> Result<(), LearnAbsent> {
        if self.thread.is_some() {
            return Ok(());
        }
        let Some((group, tx, covered, initial_gap_owed)) = self.pending.take() else {
            return Ok(());
        };
        let worker_state = Arc::clone(&self.state);
        match std::thread::Builder::new()
            .name("p11scope-learn".to_string())
            .spawn(move || drain_loop(group, tx, worker_state, covered, initial_gap_owed))
        {
            Ok(thread) => {
                self.thread = Some(thread);
                Ok(())
            }
            Err(error) => Err(LearnAbsent {
                reason: format!("learn thread spawn failed: {error}"),
            }),
        }
    }

    /// Stops the drain and joins it, reporting whether a tail was lost:
    /// an unsent message or unread queue contents at shutdown, or a
    /// drain thread that panicked. The engine files that loss loudly
    /// (the overflow aggregate).
    pub(crate) fn shutdown_and_join(&mut self) -> bool {
        self.state.shutdown.store(true, Ordering::Release);
        // A never-begun learner holds the only sender: drop it so the
        // channel closes terminally instead of dangling.
        self.pending = None;
        let mut lost = self.state.lost_tail.load(Ordering::Acquire);
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            lost = true;
        }
        lost || self.state.lost_tail.load(Ordering::Acquire)
    }
}

impl Drop for FileLearner {
    fn drop(&mut self) {
        let _ = self.shutdown_and_join();
    }
}

/// Bound on the retained covered-filesystem set: the mount table it
/// mirrors is itself size-capped below, and the set never retains a
/// mount point the current table no longer shows.
const MARK_COVERAGE_CAP: usize = 8192;

/// Decides filesystem-mark coverage for one (re-)mark pass: each
/// visible mount is offered to `mark` by its point; a success covers
/// the path it resolved through, whether that is the snapshot mount
/// itself (a direct hit) or a shadowing mount the open resolved to
/// instead (a file bind's underlying filesystem, an overmount that
/// landed after the snapshot, a triggered automount: opens at the
/// path hit the marked filesystem either way). A failure still
/// covers the path when the snapshot mount carries a retained mark
/// from an earlier pass on the *same mount identity* (the startup
/// marks survive the post-setup capability shed and keep
/// delivering), and a failure on a mount never covered before
/// counts as uncovered. The next covered set retains exactly the
/// mounts actually marked plus the retained snapshot mounts still
/// visible — never a shadowed snapshot identity, so a shadowing
/// mount that goes away leaves the reappeared snapshot honestly
/// uncovered. A remount or a replacement filesystem at an already
/// covered path carries a new mount id, so it never inherits the
/// dead mount's coverage. Coverage therefore comes from this
/// retained-identity set alone — traffic on older filesystems can
/// never stand in for a filesystem whose mark failed. Returns the
/// next covered set and the uncovered-visible count; a nonzero
/// count owes the finite unavailable-learning gap.
pub(crate) fn evaluate_mark_coverage(
    previously_covered: &BTreeSet<MountIdentity>,
    visible: &[MountToMark],
    mut mark: impl FnMut(&std::path::Path) -> Option<MountIdentity>,
) -> (BTreeSet<MountIdentity>, usize) {
    // Each entry is judged by its own mark outcome alone, so one
    // pass over the snapshot cannot credit the wrong mount however
    // the table is ordered. The callback returns the identity of
    // the mount actually marked, derived from the held descriptor
    // it marked — never the snapshot's say-so. A successful mark
    // covers its path even when the open resolved to a different
    // mount than the snapshot (the marked filesystem is what the
    // path reaches now); only a failed mark on a never-covered
    // mount owes the gap.
    let mut covered = BTreeSet::new();
    let mut uncovered = 0usize;
    for mount in visible {
        if let Some(identity) = mount.identity
            && previously_covered.contains(&identity)
            && covered.len() < MARK_COVERAGE_CAP
        {
            covered.insert(identity);
            continue;
        }
        match mark(&mount.point) {
            Some(marked) if covered.len() < MARK_COVERAGE_CAP => {
                covered.insert(marked);
            }
            _ => uncovered += 1,
        }
    }
    (covered, uncovered)
}

/// The mounts a mark pass must cover, from the observer's mount
/// table; an unreadable table falls back to `/` alone, its identity
/// unknown until a later pass can parse the table.
fn visible_mounts() -> Vec<MountToMark> {
    const MOUNTINFO_CAP: usize = 1024 * 1024;
    let text = std::fs::read_to_string("/proc/self/mountinfo")
        .ok()
        .filter(|text| text.len() <= MOUNTINFO_CAP);
    text.as_deref()
        .map(mounts_for_marks)
        .filter(|mounts| !mounts.is_empty())
        .unwrap_or_else(|| {
            vec![MountToMark {
                point: std::path::PathBuf::from("/"),
                identity: None,
            }]
        })
}

/// The mount identity of a held descriptor: its fdinfo mount id
/// keys into the pass snapshot for the snapshot device, so a mark
/// placed through this descriptor is credited to the mount actually
/// marked. The table device wins over the fd's own because btrfs
/// reports a per-subvolume anonymous device from fstat while
/// mountinfo carries the shared superblock device — comparing fd
/// devices would leave every subvolume mount falsely uncovered. A
/// mount id absent from the snapshot (an automount the open itself
/// triggered, an overmount that landed after the snapshot) falls
/// back to the fd's own device: the mark went somewhere real, and
/// the fallback credits that mount instead of silence. `None` only
/// when the mount id cannot be read at all.
fn mount_identity_of_fd(fd: &OwnedFd, mounts: &[MountToMark]) -> Option<MountIdentity> {
    let text = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).ok()?;
    let mount_id = text.lines().find_map(|line| {
        line.strip_prefix("mnt_id:")
            .and_then(|value| value.trim().parse().ok())
    })?;
    if let Some(identity) = mounts
        .iter()
        .filter_map(|mount| mount.identity)
        .find(|identity| identity.mount_id == mount_id)
    {
        return Some(identity);
    }
    // SAFETY: fstat on our own held descriptor into a zeroed stat.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0 {
        return None;
    }
    Some(MountIdentity {
        mount_id,
        dev_major: libc::major(stat.st_dev),
        dev_minor: libc::minor(stat.st_dev),
    })
}

/// Opens a mount point for a filesystem mark: a real `O_RDONLY`
/// directory handle, never `O_PATH` (the kernel rejects
/// `FAN_MARK_FILESYSTEM` through an `O_PATH` fd with `EBADF`).
/// `O_DIRECTORY | O_NOFOLLOW` bind the handle to the directory
/// itself, so the mark and its identity credit cannot slide onto a
/// non-directory or through a trailing symlink. `None` (an
/// unopenable mount point) is a named gap, never silent coverage.
fn open_mount_for_mark(point: &std::path::Path) -> Option<OwnedFd> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(point.as_os_str().as_bytes()).ok()?;
    // SAFETY: libc call; the NUL-terminated path is valid.
    let raw = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return None;
    }
    // SAFETY: `raw` is a fresh owned descriptor from the open above.
    Some(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Opens a file bind mount for a filesystem mark: a real `O_RDONLY`
/// file handle, never `O_PATH` (the kernel rejects
/// `FAN_MARK_FILESYSTEM` through an `O_PATH` fd with `EBADF`) and
/// never `O_DIRECTORY` (a file bind refuses it with `ENOTDIR`).
/// `O_NONBLOCK` keeps a fifo bind from hanging the pass;
/// `O_NOFOLLOW` refuses a trailing symlink instead of marking
/// through it. The mark covers the file's filesystem — the same
/// superblock its own mount entry marks — so the bind needs no
/// separate filesystem of its own. `None` (an unopenable file) is
/// a named gap, never silent coverage.
fn open_file_for_mark(point: &std::path::Path) -> Option<OwnedFd> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(point.as_os_str().as_bytes()).ok()?;
    // SAFETY: libc call; the NUL-terminated path is valid.
    let raw = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return None;
    }
    // SAFETY: `raw` is a fresh owned descriptor from the open above.
    Some(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Adds one filesystem mark through a held descriptor for the
/// mount point (the NULL-pathname fd form), returning the marked
/// mount's identity read from that same descriptor against the
/// pass snapshot. Directories mark through the directory handle;
/// file bind mounts (a file where the snapshot shows a mount
/// point) mark through a file handle, covering the file's
/// filesystem. `None` when the mount point cannot be held (for
/// example an `O_RDONLY` open refused with `EACCES`), when the
/// kernel refuses the mark (for example without `CAP_SYS_ADMIN`
/// after the capability shed), or when the identity cannot be
/// read: an uncredited mark is a named gap, never silent coverage.
/// Marking the held object — not re-resolving the pathname inside
/// the syscall — is what binds the credit to the mount actually
/// marked when an overmount races the mountinfo snapshot.
fn try_mark_filesystem(
    group: &OwnedFd,
    point: &std::path::Path,
    mounts: &[MountToMark],
) -> Option<MountIdentity> {
    let held = open_mount_for_mark(point).or_else(|| open_file_for_mark(point))?;
    let identity = mount_identity_of_fd(&held, mounts);
    // SAFETY: libc call; the group and held descriptors are valid,
    // and a NULL pathname marks the held descriptor's object.
    let rc = unsafe {
        libc::fanotify_mark(
            group.as_raw_fd(),
            libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
            libc::FAN_OPEN,
            held.as_raw_fd(),
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return None;
    }
    identity
}

/// One (re-)mark pass over the visible filesystems, retaining the
/// coverage earlier passes established. Returns the next covered set
/// and how many visible filesystems it leaves uncovered.
fn mark_visible_filesystems(
    group: &OwnedFd,
    previously_covered: &BTreeSet<MountIdentity>,
) -> (BTreeSet<MountIdentity>, usize) {
    let mounts = visible_mounts();
    evaluate_mark_coverage(previously_covered, &mounts, |point| {
        try_mark_filesystem(group, point, &mounts)
    })
}

/// Reads the `Pid:` of a pidfd from its fdinfo: the pid belongs to the
/// pinned task, so it cannot name a reused process. A dead task reads
/// `Pid: -1`, which fails the `u32` parse and yields `None`: callers
/// must treat that as "loader already gone", never as a skip.
fn pid_of_pidfd(pidfd: &OwnedFd) -> Option<u32> {
    let text = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd())).ok()?;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Pid:") {
            return value.trim().parse().ok();
        }
    }
    None
}

/// The tally pid for one event: the reuse-immune pidfd pid when the
/// loader is still alive, else the metadata pid the kernel captured at
/// event time. The metadata fallback is lower-bound-correct for counts
/// (a dead pid is still a real missed run; reuse can only merge two
/// runs into one tally entry) but must never name an executable.
fn tally_pid(event: &ParsedFanotifyEvent, pidfd: Option<&OwnedFd>) -> Option<u32> {
    if let Some(pid) = pidfd.and_then(pid_of_pidfd) {
        return Some(pid);
    }
    u32::try_from(event.pid).ok().filter(|pid| *pid > 0)
}

/// Shutdown coordination between the learner handle and the drain
/// thread: `shutdown` stops the loop, `lost_tail` records an
/// unsent/unread tail so the engine files loss loudly instead of
/// dropping it silently at the boundary.
#[derive(Debug, Default)]
struct LearnShutdownState {
    shutdown: AtomicBool,
    lost_tail: AtomicBool,
}

/// Sends one message, waiting past a full channel in 1 ms steps so a
/// shutdown (or a dropped receiver) always breaks the wait: a blocking
/// send here could wedge the engine's drop on a full channel. Returns
/// false when the drain must exit; an unsent message at shutdown marks
/// the lost tail.
fn send_learn(
    tx: &SyncSender<LearnMsg>,
    state: &Arc<LearnShutdownState>,
    mut msg: LearnMsg,
) -> bool {
    loop {
        if state.shutdown.load(Ordering::Acquire) {
            state.lost_tail.store(true, Ordering::Release);
            return false;
        }
        match tx.try_send(msg) {
            Ok(()) => return true,
            Err(std::sync::mpsc::TrySendError::Full(returned)) => {
                msg = returned;
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => return false,
        }
    }
}

/// Drain counters for the periodic `-v` telemetry line: counts only,
/// never paths, pids or file bytes.
#[derive(Default)]
struct DrainStats {
    events: u64,
    checked: u64,
    proved: u64,
    sent_candidates: u64,
    sent_loads: u64,
    overflows: u64,
    unreadable: u64,
}

/// The drain: poll/read the group, decide each opened file at most once
/// per generation, hold provider fds, and forward candidates, load
/// tallies and overflow. Never blocks the engine; the engine never
/// blocks it past the bounded channel (then the kernel queue absorbs,
/// then overflow names the loss).
fn drain_loop(
    group: OwnedFd,
    tx: SyncSender<LearnMsg>,
    state: Arc<LearnShutdownState>,
    mut covered: BTreeSet<MountIdentity>,
    initial_gap_owed: bool,
) {
    // Scheduling note: loader processes live ~15 ms, so the drain
    // wants prompt scheduling to name them (files still stage via
    // the unknown-loader reason when it loses the race). The observer
    // sheds CAP_SYS_NICE at startup (caps least privilege), so no
    // setpriority here could help; the drain inherits the observer's
    // nice, and an invoker-niced observer degrades naming latency
    // honestly instead of misnaming.
    let raw = group.as_raw_fd();
    let self_pid = std::process::id();
    let mut cache = LearnCache::new();
    let mut stats = DrainStats::default();
    let mut buf = vec![0u8; 64 * 1024];
    let mut last_remark = std::time::Instant::now();
    let mut unavailable_sent = false;
    // The startup pass already left a visible filesystem uncovered:
    // name that partial coverage now, once (data-always), instead of
    // letting traffic on the covered filesystems stand in for it.
    if initial_gap_owed {
        unavailable_sent = true;
        if !send_learn(&tx, &state, LearnMsg::Unavailable) {
            return;
        }
    }
    'drain: while !state.shutdown.load(Ordering::Acquire) {
        let mut polled = libc::pollfd {
            fd: raw,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: libc poll on one valid fd with a 200 ms timeout.
        let ready = unsafe { libc::poll(&mut polled, 1, 200) };
        if ready < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if last_remark.elapsed() >= std::time::Duration::from_secs(30) {
            last_remark = std::time::Instant::now();
            // Coverage is the retained-mark set, never event traffic:
            // a failed re-mark of a retained filesystem is harmless
            // (its startup mark still delivers), but a visible
            // filesystem that no pass ever covered — a new mount the
            // post-shed drain cannot mark — files the finite
            // unavailable-learning gap once, however busy the covered
            // filesystems are. The capture continues (data-always).
            let (next_covered, uncovered) = mark_visible_filesystems(&group, &covered);
            covered = next_covered;
            if uncovered > 0 && !unavailable_sent {
                unavailable_sent = true;
                if !send_learn(&tx, &state, LearnMsg::Unavailable) {
                    break 'drain;
                }
            }
            if crate::run::capture_diagnostics_on() {
                eprintln!(
                    "p11scope: file learning: {} events, {} checked, {} providers, {} staged, {} loads, {} overflows, {} unreadable",
                    stats.events,
                    stats.checked,
                    stats.proved,
                    stats.sent_candidates,
                    stats.sent_loads,
                    stats.overflows,
                    stats.unreadable,
                );
            }
        }
        if ready == 0 {
            continue;
        }
        // SAFETY: libc read into a live buffer; NONBLOCK so no stall.
        let read = unsafe { libc::read(raw, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if read <= 0 {
            continue;
        }
        let mut offset = 0usize;
        while offset < read as usize {
            let event = match parse_fanotify_event(&buf[offset..read as usize]) {
                Ok(event) => event,
                Err(_) => {
                    // Unparseable tail: best-effort close of the fds
                    // its length fields still describe, then stop.
                    close_unread_tail(&buf, offset, read as usize);
                    state.lost_tail.store(true, Ordering::Release);
                    break;
                }
            };
            offset += event.total_len;
            stats.events = stats.events.saturating_add(1);
            // Take ownership of the pidfd first: every path below closes.
            // SAFETY: the kernel sent an owned pidfd; negatives are not fds.
            let pidfd = match event.pidfd {
                Some(fd) if fd >= 0 => {
                    set_cloexec(fd);
                    Some(unsafe { OwnedFd::from_raw_fd(fd) })
                }
                _ => None,
            };
            if event.overflow {
                stats.overflows = stats.overflows.saturating_add(1);
                let (next_covered, _) = mark_visible_filesystems(&group, &covered);
                covered = next_covered;
                if !send_learn(&tx, &state, LearnMsg::QueueOverflow) {
                    close_unread_tail(&buf, offset, read as usize);
                    break 'drain;
                }
                continue;
            }
            if event.fd < 0 {
                continue;
            }
            set_cloexec(event.fd);
            // SAFETY: the kernel sent an owned event fd.
            let file = unsafe { std::fs::File::from_raw_fd(event.fd) };
            if event.pid as u32 == self_pid {
                continue;
            }
            let generation = match file_generation(&file) {
                Ok(generation) => generation,
                Err(_) => continue,
            };
            if !cache.needs_check(generation) {
                if cache.decided_provider(generation) != Some(true) {
                    continue;
                }
                // A later open of a sent file: tally the load. The pid
                // falls back to the metadata capture when the loader is
                // already gone (lower-bound-correct for counts).
                let Some(pid) = tally_pid(&event, pidfd.as_ref()) else {
                    continue;
                };
                let (dev, ino) = (generation.0, generation.1);
                if !send_learn(&tx, &state, LearnMsg::Load { dev, ino, pid }) {
                    close_unread_tail(&buf, offset, read as usize);
                    break 'drain;
                }
                stats.sent_loads = stats.sent_loads.saturating_add(1);
                continue;
            }
            stats.checked = stats.checked.saturating_add(1);
            // Name the loader now, at event receipt and bracketed by
            // pidfd liveness, before the ELF proof spends time a
            // one-shot loader does not have.
            let early_loader = pidfd.as_ref().map(loader_exe_for_pidfd);
            let proved = match check_elf_provider(&file) {
                Ok(proved) => proved,
                Err(_) => {
                    // Unreadable now: not cached, retried on the next open.
                    stats.unreadable = stats.unreadable.saturating_add(1);
                    continue;
                }
            };
            if !proved {
                cache.note_decided(generation, false);
                continue;
            }
            stats.proved = stats.proved.saturating_add(1);
            // Provider-positive: tally this first run, name its loader
            // from the pinned pidfd when still alive (else the finite
            // unknown reason — the file still stages), and send Load
            // ahead of the candidate so the staged note counts it.
            let tally = tally_pid(&event, pidfd.as_ref());
            let (loader_exe, loader_unknown_reason) =
                early_loader.unwrap_or((None, Some(LOADER_EXE_UNREADABLE_REASON)));
            let Some(display_path) = display_path_for(&file) else {
                // Not cached: a later open retries instead of losing
                // this proved provider for the whole capture.
                stats.unreadable = stats.unreadable.saturating_add(1);
                continue;
            };
            let (dev, ino) = (generation.0, generation.1);
            if let Some(pid) = tally {
                if !send_learn(&tx, &state, LearnMsg::Load { dev, ino, pid }) {
                    close_unread_tail(&buf, offset, read as usize);
                    break 'drain;
                }
                stats.sent_loads = stats.sent_loads.saturating_add(1);
            }
            let candidate = LearnedCandidate {
                file,
                dev,
                ino,
                display_path,
                loader_exe,
                loader_unknown_reason,
            };
            if !send_learn(&tx, &state, LearnMsg::Candidate(candidate)) {
                close_unread_tail(&buf, offset, read as usize);
                break 'drain;
            }
            // Only a sent candidate settles the generation: caching a
            // positive before the send would lose the file silently
            // if the send (or the display read above) failed.
            cache.note_decided(generation, true);
            stats.sent_candidates = stats.sent_candidates.saturating_add(1);
        }
    }
    // Exiting with a readable queue means unprocessed events are lost
    // with the group fd: mark the tail so the engine files it loudly.
    let mut final_poll = libc::pollfd {
        fd: raw,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: libc poll on one valid fd with a zero timeout.
    let ready = unsafe { libc::poll(&mut final_poll, 1, 0) };
    if ready > 0 {
        state.lost_tail.store(true, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::io::AsRawFd;

    /// The operator off switch disables learning only for exactly
    /// `P11SCOPE_DISABLE_FILE_LEARNING=1`; unset and every other value
    /// keep the default (learning on).
    #[test]
    fn file_learning_off_switch_requires_exact_one() {
        assert_eq!(
            super::DISABLE_FILE_LEARNING_ENV,
            "P11SCOPE_DISABLE_FILE_LEARNING"
        );
        assert!(super::file_learning_disabled(Some("1")));
        assert!(!super::file_learning_disabled(None));
        assert!(!super::file_learning_disabled(Some("")));
        assert!(!super::file_learning_disabled(Some("0")));
        assert!(!super::file_learning_disabled(Some("true")));
        assert!(!super::file_learning_disabled(Some(" 1")));
    }

    /// The mount-namespace scope gap fires only when both namespace
    /// links read and differ; an unreadable link (an unprivileged
    /// observer cannot read `/proc/1/ns/mnt`) never files a false gap.
    #[test]
    fn mount_namespace_gap_requires_two_readable_different_links() {
        assert!(super::mount_namespaces_differ(
            Some("mnt:[4026532000]"),
            Some("mnt:[4026531832]"),
        ));
        assert!(!super::mount_namespaces_differ(
            Some("mnt:[4026531832]"),
            Some("mnt:[4026531832]"),
        ));
        assert!(!super::mount_namespaces_differ(
            None,
            Some("mnt:[4026531832]"),
        ));
        assert!(!super::mount_namespaces_differ(
            Some("mnt:[4026532000]"),
            None,
        ));
        assert!(!super::mount_namespaces_differ(None, None));
    }

    /// A non-ELF open drains and closes: the classifier says no, the file
    /// is recorded by identity only, and the second sighting needs no
    /// check. The cache retains no path (privacy twin).
    #[test]
    fn learn_fd_event_closes_non_elf_without_naming_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notes.txt");
        std::fs::write(&path, b"not an elf file at all").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        assert!(!super::check_elf_provider(&file).unwrap());
        let generation = super::file_generation(&file).unwrap();
        let mut cache = super::LearnCache::new();
        assert!(cache.needs_check(generation));
        cache.note_decided(generation, false);
        assert!(
            !cache.needs_check(generation),
            "each file generation is checked once: {generation:?}"
        );
        assert_eq!(cache.decided_provider(generation), Some(false));
        assert!(
            !format!("{cache:?}").contains("notes"),
            "a negative entry must not retain the path: {cache:?}"
        );
    }

    /// An ELF without PKCS#11 entry points goes to the negative set
    /// silently: no candidate, no display path, no gap.
    #[test]
    fn learn_elf_without_entry_points_goes_negative_silently() {
        let dir = tempfile::tempdir().unwrap();
        let c = dir.path().join("plain.c");
        let so = dir.path().join("libplain.so");
        std::fs::write(&c, "int unrelated(void){return 1;}\n").unwrap();
        assert!(
            std::process::Command::new("gcc")
                .args(["-shared", "-fPIC", "-o"])
                .arg(&so)
                .arg(&c)
                .status()
                .unwrap()
                .success()
        );
        let file = std::fs::File::open(&so).unwrap();
        assert!(!super::check_elf_provider(&file).unwrap());
        let (dev, ino) = super::file_identity(&file).unwrap();
        assert_ne!((dev, ino), (0, 0));
    }

    /// A provider-positive fd reports its readlink display path and the
    /// loading program's exe; the held fd stays open for the pin worker.
    #[test]
    fn learn_provider_fd_reports_display_path_and_loader() {
        let dir = tempfile::tempdir().unwrap();
        let c = dir.path().join("vendor.c");
        let so = dir.path().join("libvendor.so");
        std::fs::write(
            &c,
            "unsigned long C_GetFunctionList(void **out){ (void)out; return 5; }\n",
        )
        .unwrap();
        assert!(
            std::process::Command::new("gcc")
                .args(["-shared", "-fPIC", "-o"])
                .arg(&so)
                .arg(&c)
                .status()
                .unwrap()
                .success()
        );
        let file = std::fs::File::open(&so).unwrap();
        assert!(
            super::check_elf_provider(&file).unwrap(),
            "the entry-point export proves a provider"
        );
        let display = super::display_path_for(&file).unwrap();
        assert!(
            display.ends_with("libvendor.so"),
            "display is the readlink path: {display}"
        );
        let (exe, reason) = super::resolve_loader_exe(std::process::id());
        let own = std::fs::read_link("/proc/self/exe")
            .unwrap()
            .to_string_lossy()
            .into_owned();
        assert_eq!(exe.as_deref(), Some(own.as_str()));
        assert_eq!(reason, None);
        // The held fd is still open: the pin worker opens /proc/self/fd/N.
        let reopened = std::fs::File::open(format!("/proc/self/fd/{}", file.as_raw_fd()));
        assert!(reopened.is_ok());
    }

    /// A fifo answers `not a provider` without blocking: the drain must
    /// never pread a non-regular file (a blocking fifo read would wedge
    /// the single drain thread).
    #[test]
    fn learn_fifo_is_a_fast_certain_negative() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("pipe");
        let path = std::ffi::CString::new(fifo.to_string_lossy().into_owned()).unwrap();
        // SAFETY: mkfifo on an owned path; mode bits only.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o644) }, 0);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&fifo)
            .unwrap();
        assert!(!super::check_elf_provider(&file).unwrap());
    }

    /// An unidentifiable file is an error, never a cached negative: the
    /// drain retries it on the next open instead of missing a file that
    /// was mid-write at first sight.
    #[test]
    fn learn_unidentifiable_file_is_uncached() {
        let dir = tempfile::tempdir().unwrap();
        let broken = dir.path().join("broken.so");
        std::fs::write(&broken, [0x7fu8, b'E', b'L', b'F', 2, 1, 1, 0]).unwrap();
        let file = std::fs::File::open(&broken).unwrap();
        assert!(super::check_elf_provider(&file).is_err());
    }

    /// The entry-point pre-filter agrees with the full parse: providers
    /// pass, plain ELFs refuse, and anything doubtful fails open to the
    /// full authoritative check.
    #[test]
    fn learn_prefilter_admits_only_possible_providers() {
        let dir = tempfile::tempdir().unwrap();
        let build = |name: &str, body: &str| {
            let c = dir.path().join(format!("{name}.c"));
            let so = dir.path().join(format!("lib{name}.so"));
            std::fs::write(&c, body).unwrap();
            assert!(
                std::process::Command::new("gcc")
                    .args(["-shared", "-fPIC", "-o"])
                    .arg(&so)
                    .arg(&c)
                    .status()
                    .unwrap()
                    .success()
            );
            std::fs::File::open(&so).unwrap()
        };
        let provider = build(
            "prefilter_vendor",
            "unsigned long C_GetFunctionList(void **out){ (void)out; return 5; }\n",
        );
        assert!(super::elf_may_export_entry_points(&provider).unwrap());
        let plain = build("prefilter_plain", "int unrelated(void){return 1;}\n");
        assert!(!super::elf_may_export_entry_points(&plain).unwrap());
        let truncated = dir.path().join("truncated.so");
        std::fs::write(&truncated, [0x7fu8, b'E', b'L', b'F', 2, 1, 1, 0]).unwrap();
        let file = std::fs::File::open(&truncated).unwrap();
        assert!(super::elf_may_export_entry_points(&file).unwrap());
    }

    /// A loader that already exited resolves to the one finite reason,
    /// never to a reused pid's executable.
    #[test]
    fn learn_dead_loader_exe_is_a_finite_reason() {
        let (exe, reason) = super::resolve_loader_exe(u32::MAX);
        assert_eq!(exe, None);
        assert_eq!(reason, Some(super::LOADER_EXE_UNREADABLE_REASON));
    }

    /// Opens a pidfd for a child the test owns (pidfd_open, Linux 5.3+).
    fn test_pidfd(pid: u32) -> std::os::fd::OwnedFd {
        use std::os::unix::io::FromRawFd as _;
        // SAFETY: pidfd_open syscall with a plain pid and no flags.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(fd >= 0, "pidfd_open: {}", std::io::Error::last_os_error());
        // SAFETY: the syscall returned an owned fd.
        unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) }
    }

    /// A still-live loader is named through its pidfd bracket; once it
    /// exits, the same pidfd yields only the finite unknown — an
    /// exited (potentially recycled) pid is never named.
    #[test]
    fn learn_loader_exe_brackets_pidfd_liveness() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pidfd = test_pidfd(child.id());
        let (exe, reason) = super::loader_exe_for_pidfd(&pidfd);
        assert_eq!(reason, None, "live loader names without a reason");
        assert!(
            exe.as_deref().is_some_and(|exe| exe.ends_with("sleep")),
            "the live sleeper is named: {exe:?}"
        );
        child.kill().unwrap();
        child.wait().unwrap();
        // The pidfd turns readable at exit; give the bracket a moment
        // only if the scheduler has not delivered it yet.
        for _ in 0..200 {
            if super::pidfd_exited(&pidfd) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(super::pidfd_exited(&pidfd), "exit makes the pidfd readable");
        let (exe, reason) = super::loader_exe_for_pidfd(&pidfd);
        assert_eq!(exe, None, "an exited loader is never named");
        assert_eq!(reason, Some(super::LOADER_EXE_UNREADABLE_REASON));
    }

    /// Kernel-handed fds get CLOEXEC explicitly, not by propagation.
    #[test]
    fn learn_set_cloexec_sets_the_flag() {
        let file = std::fs::File::open("/dev/null").unwrap();
        let raw = file.as_raw_fd();
        // SAFETY: fcntl on our own live fd.
        let before = unsafe { libc::fcntl(raw, libc::F_GETFD) };
        assert!(before >= 0);
        // SAFETY: same fd; clear first so the helper must do the work.
        unsafe { libc::fcntl(raw, libc::F_SETFD, before & !libc::FD_CLOEXEC) };
        super::set_cloexec(raw);
        // SAFETY: same fd.
        let after = unsafe { libc::fcntl(raw, libc::F_GETFD) };
        assert!(after & libc::FD_CLOEXEC != 0, "FD_CLOEXEC set: {after}");
    }

    /// Filesystem marks cover real filesystems; pseudo filesystems are
    /// never marked; mountinfo escapes are decoded for the mark path.
    #[test]
    fn learn_mount_marks_skip_pseudo_filesystems() {
        let table = "36 1 0:31 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n\
             37 1 0:32 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sysfs rw\n\
             38 1 0:33 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - cgroup2 cgroup2 rw\n\
             39 1 0:34 / /sys/kernel/debug rw,nosuid,nodev,noexec,relatime - debugfs debugfs rw\n\
             40 1 0:35 / /sys/kernel/tracing rw,nosuid,nodev,noexec,relatime - tracefs tracefs rw\n\
             41 1 0:36 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime - bpf bpf rw\n\
             1 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
             42 1 0:37 / /dev tmpfs rw,nosuid,relatime - tmpfs tmpfs rw\n\
             43 1 0:38 / /mnt/with\\040space rw,relatime - tmpfs tmpfs rw\n\
             99 1 0:99 / /mnt/ovl rw,relatime - overlay overlay rw,lowerdir=/l,upperdir=/u,workdir=/w\n";
        let mut marks: Vec<String> = super::mounts_for_marks(table)
            .iter()
            .map(|mount| mount.point.to_string_lossy().into_owned())
            .collect();
        marks.sort();
        assert_eq!(marks, vec!["/", "/dev", "/mnt/ovl", "/mnt/with space"]);
    }

    fn mnt(mount_id: u64, dev_major: u32, dev_minor: u32) -> super::MountIdentity {
        super::MountIdentity {
            mount_id,
            dev_major,
            dev_minor,
        }
    }

    fn visible_mount(
        point: &str,
        mount_id: u64,
        dev_major: u32,
        dev_minor: u32,
    ) -> super::MountToMark {
        super::MountToMark {
            point: std::path::PathBuf::from(point),
            identity: Some(mnt(mount_id, dev_major, dev_minor)),
        }
    }

    /// The mark parser carries mount identity (mount id + filesystem
    /// device) beside each point, and an overmounted point keeps the
    /// topmost (last) mount's identity: the path resolves there.
    #[test]
    fn learn_mount_marks_carry_mount_identity() {
        let table = "51 1 8:1 / /mnt/provider rw,relatime - ext4 /dev/sda1 rw\n\
             68 1 8:2 / /mnt/provider rw,relatime - ext4 /dev/sda2 rw\n\
             70 1 0:40 / /data rw,relatime - tmpfs tmpfs rw\n";
        let mounts = super::mounts_for_marks(table);
        assert_eq!(mounts.len(), 2, "the overmount shadows the lower mount");
        let provider = mounts
            .iter()
            .find(|mount| mount.point.as_os_str() == "/mnt/provider")
            .expect("provider mount parsed");
        assert_eq!(provider.identity, Some(mnt(68, 8, 2)));
        let data = mounts
            .iter()
            .find(|mount| mount.point.as_os_str() == "/data")
            .expect("data mount parsed");
        assert_eq!(data.identity, Some(mnt(70, 0, 40)));
    }

    /// The mark fd is a real `O_RDONLY` directory handle, never
    /// `O_PATH`: the kernel rejects `FAN_MARK_FILESYSTEM` through an
    /// `O_PATH` fd with `EBADF`, so the held descriptor opens
    /// `O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC` and still
    /// yields the held-object identity. A non-directory and a
    /// trailing symlink refuse (a fail-closed named gap, never a
    /// mark on the wrong object).
    #[test]
    fn learn_mark_fd_is_a_readable_directory_handle() {
        let held =
            super::open_mount_for_mark(std::path::Path::new("/")).expect("root opens for marking");
        // SAFETY: fcntl on our own live fd.
        let flags = unsafe { libc::fcntl(held.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0, "F_GETFL reads the mark fd flags");
        assert_eq!(
            flags & libc::O_ACCMODE,
            libc::O_RDONLY,
            "the mark fd opens O_RDONLY (O_PATH marks fail EBADF): {flags}"
        );
        assert_eq!(
            flags & libc::O_PATH,
            0,
            "the mark fd is never O_PATH: {flags}"
        );
        assert!(
            flags & libc::O_DIRECTORY != 0,
            "the mark fd pins a directory: {flags}"
        );
        assert!(
            flags & libc::O_NOFOLLOW != 0,
            "the mark fd never follows a trailing symlink: {flags}"
        );
        // SAFETY: fcntl on our own live fd.
        let fd_flags = unsafe { libc::fcntl(held.as_raw_fd(), libc::F_GETFD) };
        assert!(
            fd_flags & libc::FD_CLOEXEC != 0,
            "the mark fd is close-on-exec: {fd_flags}"
        );
        assert!(
            super::mount_identity_of_fd(&held, &[]).is_some(),
            "the held object still yields its mount identity"
        );
        // O_DIRECTORY: a regular file refuses.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("plain");
        std::fs::write(&file, "not a mount point").unwrap();
        assert!(
            super::open_mount_for_mark(&file).is_none(),
            "a non-directory is never a mark fd"
        );
        // O_NOFOLLOW: a trailing symlink refuses instead of marking
        // through to whatever it points at.
        let link = dir.path().join("link");
        std::os::unix::fs::symlink("/", &link).unwrap();
        assert!(
            super::open_mount_for_mark(&link).is_none(),
            "a symlink is never a mark fd"
        );
    }

    /// A failed re-mark of an already covered filesystem is not a
    /// coverage loss: the startup mark survives the capability shed
    /// and keeps delivering, so post-shed add failures on retained
    /// filesystems file no gap.
    #[test]
    fn learn_retained_mark_failure_is_not_a_coverage_gap() {
        let covered: std::collections::BTreeSet<super::MountIdentity> =
            [mnt(51, 8, 1), mnt(52, 8, 2)].into_iter().collect();
        let visible = vec![
            visible_mount("/", 51, 8, 1),
            visible_mount("/data", 52, 8, 2),
        ];
        // Every add fails now (no CAP_SYS_ADMIN after the shed).
        let (next, uncovered) = super::evaluate_mark_coverage(&covered, &visible, |_| None);
        assert_eq!(uncovered, 0, "retained marks stay covered");
        assert_eq!(next, covered);
    }

    /// A different filesystem mounted at an already covered path does
    /// not inherit the old mark: the old mark died with the unmounted
    /// superblock, so a failed re-mark of the replacement (new mount
    /// id, new device, same path) is uncovered and owes the gap.
    #[test]
    fn learn_replacement_filesystem_at_covered_path_is_uncovered() {
        let covered: std::collections::BTreeSet<super::MountIdentity> =
            [mnt(51, 8, 1)].into_iter().collect();
        let visible = vec![visible_mount("/mnt/provider", 68, 8, 2)];
        let (next, uncovered) = super::evaluate_mark_coverage(&covered, &visible, |_| None);
        assert_eq!(uncovered, 1, "the replacement filesystem was never marked");
        assert!(next.is_empty(), "the dead mount's coverage is not retained");
    }

    /// The same device remounted at the same path is a new mount: its
    /// predecessor's mark died at unmount, so device equality alone
    /// must not inherit coverage either.
    #[test]
    fn learn_remount_of_same_device_is_uncovered() {
        let covered: std::collections::BTreeSet<super::MountIdentity> =
            [mnt(51, 8, 1)].into_iter().collect();
        let visible = vec![visible_mount("/mnt/provider", 68, 8, 1)];
        let (next, uncovered) = super::evaluate_mark_coverage(&covered, &visible, |_| None);
        assert_eq!(uncovered, 1, "a remount is not the marked mount");
        assert!(next.is_empty());
    }

    /// The very same mount (same mount id and device) seen at a new
    /// path after a move keeps its retained mark: identity, not the
    /// path spelling, is what coverage keys on.
    #[test]
    fn learn_same_mount_at_new_path_stays_covered() {
        let covered: std::collections::BTreeSet<super::MountIdentity> =
            [mnt(51, 8, 1)].into_iter().collect();
        let visible = vec![visible_mount("/moved/provider", 51, 8, 1)];
        let (next, uncovered) = super::evaluate_mark_coverage(&covered, &visible, |_| None);
        assert_eq!(uncovered, 0, "the moved mount's mark still delivers");
        assert_eq!(next, covered);
    }

    /// A newly mounted filesystem whose mark fails is uncovered even
    /// while older filesystems keep delivering: coverage comes from
    /// the retained-mark set, never from traffic elsewhere.
    #[test]
    fn learn_failed_new_filesystem_mark_is_uncovered() {
        let covered: std::collections::BTreeSet<super::MountIdentity> =
            [mnt(51, 8, 1)].into_iter().collect();
        let visible = vec![
            visible_mount("/", 51, 8, 1),
            visible_mount("/mnt/new", 68, 8, 2),
        ];
        let (next, uncovered) = super::evaluate_mark_coverage(&covered, &visible, |_| None);
        assert_eq!(uncovered, 1, "the unmarked new filesystem is a gap");
        assert_eq!(next, covered, "only the retained filesystem is covered");
    }

    /// A newly mounted filesystem that marks successfully joins the
    /// covered set with no gap.
    #[test]
    fn learn_successful_new_filesystem_mark_covers_it() {
        let covered: std::collections::BTreeSet<super::MountIdentity> =
            [mnt(51, 8, 1)].into_iter().collect();
        let visible = vec![
            visible_mount("/", 51, 8, 1),
            visible_mount("/mnt/new", 68, 8, 2),
        ];
        let (next, uncovered) = super::evaluate_mark_coverage(&covered, &visible, |point| {
            (point.as_os_str() == "/mnt/new").then(|| mnt(68, 8, 2))
        });
        assert_eq!(uncovered, 0);
        assert!(next.contains(&mnt(68, 8, 2)));
        assert!(next.contains(&mnt(51, 8, 1)));
    }

    /// An overmount landing between the mountinfo snapshot and the
    /// mark covers the path through the overmount: the mark callback
    /// reports the mount actually marked, and opens at the path hit
    /// that marked filesystem, not the unreachable snapshot mount.
    /// The retained set keeps the overmount's identity alone, so
    /// after the overmount goes away a failed re-mark of the
    /// reappeared snapshot mount is uncovered, never inherited.
    #[test]
    fn learn_overmount_between_snapshot_and_mark_covers_the_path() {
        let covered = std::collections::BTreeSet::new();
        let visible = vec![visible_mount("/mnt/provider", 51, 8, 1)];
        // The syscall marked the racing overmount (68), not the
        // snapshot mount (51).
        let (next, uncovered) =
            super::evaluate_mark_coverage(&covered, &visible, |_| Some(mnt(68, 8, 2)));
        assert_eq!(uncovered, 0, "the resolving overmount is marked");
        assert!(
            !next.contains(&mnt(51, 8, 1)),
            "the shadowed mount claims no retained coverage: {next:?}"
        );
        assert!(
            next.contains(&mnt(68, 8, 2)),
            "the actually-marked mount is retained: {next:?}"
        );
        // After the overmount goes away, a failed re-mark of the
        // reappeared snapshot mount is uncovered, not retained.
        let (next, uncovered) = super::evaluate_mark_coverage(&next, &visible, |_| None);
        assert_eq!(uncovered, 1);
        assert!(next.is_empty());
    }

    /// With nothing retained, every failed mark is uncovered (the
    /// startup shape behind the unavailable-learning refusal).
    #[test]
    fn learn_no_retained_marks_counts_every_failure() {
        let covered = std::collections::BTreeSet::new();
        let visible = vec![
            visible_mount("/", 51, 8, 1),
            visible_mount("/data", 52, 8, 2),
        ];
        let (next, uncovered) = super::evaluate_mark_coverage(&covered, &visible, |_| None);
        assert_eq!(uncovered, 2);
        assert!(next.is_empty());
    }

    /// A mark placed through a shadowing mount covers the path: the
    /// open resolved to the overmount (a vng `/usr` overlay hiding
    /// `/usr/lib`, a triggered autofs), so opens at the path hit the
    /// marked filesystem, not the unreachable snapshot mount. The
    /// retained set keeps the mount actually marked, never the
    /// shadowed snapshot identity.
    #[test]
    fn learn_mark_through_shadowing_mount_covers_the_path() {
        let covered = std::collections::BTreeSet::new();
        let visible = vec![visible_mount("/usr/lib", 39, 0, 30)];
        // The syscall marked the resolving overmount (51), not the
        // snapshot mount (39).
        let (next, uncovered) =
            super::evaluate_mark_coverage(&covered, &visible, |_| Some(mnt(51, 0, 42)));
        assert_eq!(uncovered, 0, "the resolving filesystem is marked");
        assert!(
            next.contains(&mnt(51, 0, 42)),
            "the marked mount is retained: {next:?}"
        );
        assert!(
            !next.contains(&mnt(39, 0, 30)),
            "the shadowed snapshot claims no coverage: {next:?}"
        );
    }

    /// Transitive coverage never retains the snapshot identity: when
    /// the shadowing mount goes away, a failed re-mark of the
    /// reappeared snapshot mount is uncovered, not inherited. The
    /// first pass covers the path through the overmount; the second
    /// pass honestly reports the unmarked reappearance.
    #[test]
    fn learn_transitive_coverage_does_not_retain_the_snapshot() {
        let covered = std::collections::BTreeSet::new();
        let visible = vec![visible_mount("/mnt/provider", 51, 8, 1)];
        let (next, uncovered) =
            super::evaluate_mark_coverage(&covered, &visible, |_| Some(mnt(68, 8, 2)));
        assert_eq!(uncovered, 0, "the overmount's mark covers the path");
        assert_eq!(
            next,
            [mnt(68, 8, 2)].into_iter().collect(),
            "only the actually-marked mount is retained"
        );
        // The overmount is gone; the reappeared snapshot mount cannot
        // be marked (post-shed re-mark without CAP_SYS_ADMIN).
        let (next, uncovered) = super::evaluate_mark_coverage(&next, &visible, |_| None);
        assert_eq!(uncovered, 1, "the unmarked reappearance owes the gap");
        assert!(next.is_empty(), "the dead overmount is not retained");
    }

    /// An unchanged shadowed mount stays covered after the capability
    /// shed: both passes resolve `/usr/lib` (snapshot 39) to the
    /// already-marked `/usr` (51), so the post-shed re-mark failure
    /// files no gap. Reproduces the codex rv2 F1 probe
    /// `review_persistent_shadow_after_capability_shed`.
    #[test]
    fn learn_unchanged_shadow_after_capability_shed_stays_covered() {
        let covered = std::collections::BTreeSet::new();
        let visible = vec![
            visible_mount("/usr", 51, 0, 42),
            visible_mount("/usr/lib", 39, 0, 30),
        ];
        // Startup: both paths resolve to the shadowing mount 51 and
        // both marks succeed.
        let (next, uncovered) =
            super::evaluate_mark_coverage(&covered, &visible, |_| Some(mnt(51, 0, 42)));
        assert_eq!(uncovered, 0, "startup marks cover the shadowed path");
        assert_eq!(
            next,
            [mnt(51, 0, 42)].into_iter().collect(),
            "only the actually-marked mount is retained"
        );
        // Unchanged topology after the shed: the retained mount's
        // re-mark is skipped, the shadowed mount's re-mark fails,
        // but the path still resolves to the marked 51.
        let (next, uncovered) = super::evaluate_mark_coverage(&next, &visible, |_| None);
        assert_eq!(
            uncovered, 0,
            "unchanged shadow resolving to a marked mount stays covered"
        );
        assert_eq!(
            next,
            [mnt(51, 0, 42)].into_iter().collect(),
            "the marked mount stays retained, never the shadowed entry"
        );
    }

    /// A mixed pass counts exactly the failed marks: a direct hit, a
    /// shadowing-mount hit and a failure leave one gap, and the
    /// retained set holds both marked mounts.
    #[test]
    fn learn_mixed_pass_counts_only_failed_marks() {
        let covered = std::collections::BTreeSet::new();
        let visible = vec![
            visible_mount("/", 51, 8, 1),
            visible_mount("/data", 52, 8, 2),
            visible_mount("/usr/lib", 39, 0, 30),
        ];
        let (next, uncovered) = super::evaluate_mark_coverage(&covered, &visible, |point| {
            if point.as_os_str() == "/" {
                Some(mnt(51, 8, 1))
            } else if point.as_os_str() == "/usr/lib" {
                Some(mnt(68, 0, 42))
            } else {
                None
            }
        });
        assert_eq!(uncovered, 1, "only the failed mark owes a gap");
        assert!(next.contains(&mnt(51, 8, 1)));
        assert!(next.contains(&mnt(68, 0, 42)));
        assert_eq!(next.len(), 2);
    }

    /// The held descriptor's mount identity takes the snapshot
    /// device: btrfs reports a per-subvolume anonymous device from
    /// fstat while mountinfo carries the shared superblock device,
    /// so the fdinfo mount id keys into the pass table and the
    /// table's device wins. A mount id absent from the table falls
    /// back to the fd's own device (a triggered autofs whose mount
    /// postdates the snapshot), never to silence.
    #[test]
    fn learn_mount_identity_of_fd_prefers_snapshot_device() {
        let text = std::fs::read_to_string("/proc/self/mountinfo")
            .expect("the test host has a mount table");
        let mut table = super::mounts_for_marks(&text);
        assert!(!table.is_empty(), "the test host shows mounts");
        // SAFETY: open(2) on / for a held directory descriptor.
        let raw = unsafe { libc::open(c"/".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        assert!(raw >= 0, "root opens for the identity probe");
        // SAFETY: `raw` is a fresh owned descriptor from the open above.
        let held: std::os::unix::io::OwnedFd =
            unsafe { std::os::unix::io::FromRawFd::from_raw_fd(raw) };
        let fdinfo = std::fs::read_to_string(format!(
            "/proc/self/fdinfo/{}",
            std::os::unix::io::AsRawFd::as_raw_fd(&held)
        ))
        .expect("fdinfo reads");
        let mnt_id: u64 = fdinfo
            .lines()
            .find_map(|line| {
                line.strip_prefix("mnt_id:")
                    .and_then(|value| value.trim().parse().ok())
            })
            .expect("fdinfo carries mnt_id");
        // Corrupt the table device for this mount id to a value no
        // fstat can produce: the lookup must return the table's
        // device, proving the fd's own device never leaks through.
        let mut found = false;
        for mount in &mut table {
            if let Some(identity) = mount.identity.as_mut()
                && identity.mount_id == mnt_id
            {
                identity.dev_major = 0xDEAD;
                identity.dev_minor = 0xBEEF;
                found = true;
            }
        }
        assert!(found, "the table shows the held mount id");
        assert_eq!(
            super::mount_identity_of_fd(&held, &table),
            Some(mnt(mnt_id, 0xDEAD, 0xBEEF)),
            "the snapshot device wins over the fd device"
        );
        // Without the mount id in the table, the fd's own device
        // still identifies the marked mount (fail-open toward the
        // mark actually placed, never silent).
        let empty: Vec<super::MountToMark> = Vec::new();
        let fallback = super::mount_identity_of_fd(&held, &empty);
        assert_eq!(
            fallback.map(|identity| identity.mount_id),
            Some(mnt_id),
            "the fallback keeps the fdinfo mount id"
        );
    }

    /// A file bind mount (vng's `/etc/hosts`, dpkg locks) opens for
    /// marking as a real `O_RDONLY` file handle: never `O_PATH` (its
    /// marks fail `EBADF`), never `O_DIRECTORY` (files refuse it),
    /// `O_NONBLOCK` so a fifo bind cannot hang the pass, and
    /// `O_NOFOLLOW | O_CLOEXEC` like the directory handle. A
    /// trailing symlink still refuses.
    #[test]
    fn learn_file_mark_fd_opens_non_directories_for_marking() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("bind-stand-in");
        std::fs::write(&file, "a bound file").unwrap();
        let held = super::open_file_for_mark(&file).expect("a file opens for marking");
        // SAFETY: fcntl on our own live fd.
        let flags = unsafe { libc::fcntl(held.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0, "F_GETFL reads the file mark fd flags");
        assert_eq!(
            flags & libc::O_ACCMODE,
            libc::O_RDONLY,
            "the file mark fd opens O_RDONLY: {flags}"
        );
        assert_eq!(
            flags & libc::O_PATH,
            0,
            "the file mark fd is never O_PATH: {flags}"
        );
        assert_eq!(
            flags & libc::O_DIRECTORY,
            0,
            "the file mark fd carries no O_DIRECTORY: {flags}"
        );
        assert!(
            flags & libc::O_NONBLOCK != 0,
            "the file mark fd never blocks on a fifo: {flags}"
        );
        assert!(
            flags & libc::O_NOFOLLOW != 0,
            "the file mark fd never follows a trailing symlink: {flags}"
        );
        // SAFETY: fcntl on our own live fd.
        let fd_flags = unsafe { libc::fcntl(held.as_raw_fd(), libc::F_GETFD) };
        assert!(
            fd_flags & libc::FD_CLOEXEC != 0,
            "the file mark fd is close-on-exec: {fd_flags}"
        );
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&file, &link).unwrap();
        assert!(
            super::open_file_for_mark(&link).is_none(),
            "a symlink is never a mark fd"
        );
    }

    /// The drain parses the pidfd info record beside the metadata, so the
    /// loader is named from a reuse-immune handle, never a bare pid.
    #[test]
    fn learn_pidfd_info_parses_reuse_immune_handle() {
        let mut buf = vec![0u8; 24 + 8];
        buf[0..4].copy_from_slice(&32u32.to_ne_bytes());
        buf[4] = 3;
        buf[6..8].copy_from_slice(&24u16.to_ne_bytes());
        buf[8..16].copy_from_slice(&0x20u64.to_ne_bytes());
        buf[16..20].copy_from_slice(&7i32.to_ne_bytes());
        buf[20..24].copy_from_slice(&1234i32.to_ne_bytes());
        buf[24] = 4;
        buf[26..28].copy_from_slice(&8u16.to_ne_bytes());
        buf[28..32].copy_from_slice(&9i32.to_ne_bytes());
        let event = super::parse_fanotify_event(&buf).unwrap();
        assert_eq!(event.fd, 7);
        assert_eq!(event.pidfd, Some(9));
        assert!(!event.overflow);
    }

    /// A send blocked past shutdown gives up but marks the lost tail:
    /// the engine files that loss loudly instead of dropping it
    /// silently at the boundary.
    #[test]
    fn learn_blocked_send_marks_lost_tail_at_shutdown() {
        use std::sync::atomic::Ordering;
        let (tx, _rx) = std::sync::mpsc::sync_channel::<super::LearnMsg>(0);
        let state = std::sync::Arc::new(super::LearnShutdownState::default());
        // Rendezvous channel with no receiver progress: the first send
        // would block forever, so shut down first and show the send
        // gives up fast with the tail marked.
        state.shutdown.store(true, Ordering::Release);
        let file = std::fs::File::open("/bin/sh").unwrap();
        let ok = super::send_learn(
            &tx,
            &state,
            super::LearnMsg::Candidate(super::LearnedCandidate {
                file,
                dev: 1,
                ino: 2,
                display_path: "/bin/sh".to_string(),
                loader_exe: None,
                loader_unknown_reason: Some(super::LOADER_EXE_UNREADABLE_REASON),
            }),
        );
        assert!(!ok);
        assert!(state.lost_tail.load(Ordering::Acquire));
    }

    /// The tally pid falls back to the metadata capture when the
    /// loader is already gone (dead pidfds read `Pid: -1`): a dead pid
    /// is still a real missed run for the lower-bound count, but only
    /// a live pidfd ever names an executable.
    #[test]
    fn learn_tally_pid_falls_back_to_metadata_for_dead_loaders() {
        let event = |pid: i32| super::ParsedFanotifyEvent {
            fd: 7,
            pid,
            pidfd: None,
            overflow: false,
            total_len: 24,
        };
        assert_eq!(super::tally_pid(&event(4242), None), Some(4242));
        assert_eq!(super::tally_pid(&event(0), None), None);
        assert_eq!(super::tally_pid(&event(-1), None), None);
    }

    /// A queue-overflow record parses with no fds: the drain must report
    /// the loss as an aggregate gap, never as a file.
    #[test]
    fn learn_overflow_event_parses_without_fds() {
        let mut buf = vec![0u8; 24];
        buf[0..4].copy_from_slice(&24u32.to_ne_bytes());
        buf[4] = 3;
        buf[6..8].copy_from_slice(&24u16.to_ne_bytes());
        buf[8..16].copy_from_slice(&0x4000u64.to_ne_bytes());
        buf[16..20].copy_from_slice(&(-1i32).to_ne_bytes());
        buf[20..24].copy_from_slice(&(-1i32).to_ne_bytes());
        let event = super::parse_fanotify_event(&buf).unwrap();
        assert!(event.overflow);
        assert_eq!(event.fd, -1);
        assert_eq!(event.pidfd, None);
    }

    /// Live drain proof (privileged): a child process opens a provider
    /// file and the drain reports it with its display path and loader.
    /// Run with `sudo -n` (fanotify needs `CAP_SYS_ADMIN`).
    #[test]
    #[ignore = "needs CAP_SYS_ADMIN fanotify group"]
    fn learn_live_drain_reports_opened_provider() {
        let dir = tempfile::tempdir().unwrap();
        let c = dir.path().join("live.c");
        let so = dir.path().join("liblive.so");
        std::fs::write(
            &c,
            "unsigned long C_GetFunctionList(void **out){ (void)out; return 5; }\n",
        )
        .unwrap();
        assert!(
            std::process::Command::new("gcc")
                .args(["-shared", "-fPIC", "-o"])
                .arg(&so)
                .arg(&c)
                .status()
                .unwrap()
                .success()
        );
        let (mut _learner, rx) = super::FileLearner::start().expect("fanotify group (run as root)");
        _learner.begin_drain().expect("spawn drain");
        // A *child* opens the file: the drain skips the observer's own pid.
        let child = std::process::Command::new("cat")
            .arg(&so)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let mut got = None;
        while std::time::Instant::now() < deadline {
            match rx.recv_timeout(std::time::Duration::from_millis(200)) {
                Ok(super::LearnMsg::Candidate(candidate))
                    if candidate.display_path.ends_with("liblive.so") =>
                {
                    got = Some(candidate);
                    break;
                }
                Ok(_) => continue,
                Err(_) => continue,
            }
        }
        let _ = child.wait_with_output();
        let candidate = got.expect("the drain reports the opened provider");
        assert!(
            candidate.loader_exe.is_some() || candidate.loader_unknown_reason.is_some(),
            "loader named or finitely unknown"
        );
        assert_ne!((candidate.dev, candidate.ino), (0, 0));
        // A long-lived loader is named, not finitely unknown: the
        // shell opens a second provider and sleeps holding the fd, so
        // the pidfd bracket reads its exe while it provably lives.
        let so2 = dir.path().join("liblive2.so");
        std::fs::copy(&so, &so2).unwrap();
        let mut holder = std::process::Command::new("sh")
            .args(["-c", "exec 3< \"$1\"; sleep 30", "sh"])
            .arg(&so2)
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let mut got = None;
        while std::time::Instant::now() < deadline {
            match rx.recv_timeout(std::time::Duration::from_millis(200)) {
                Ok(super::LearnMsg::Candidate(candidate))
                    if candidate.display_path.ends_with("liblive2.so") =>
                {
                    got = Some(candidate);
                    break;
                }
                Ok(_) => continue,
                Err(_) => continue,
            }
        }
        let candidate = got.expect("the drain reports the held provider");
        assert!(
            candidate
                .loader_exe
                .as_deref()
                .is_some_and(|exe| exe.ends_with("/sh") || exe.ends_with("/dash")),
            "the still-live holder is named: {:?} / {:?}",
            candidate.loader_exe,
            candidate.loader_unknown_reason
        );
        holder.kill().unwrap();
        let _ = holder.wait();
    }

    /// Live drain proof across mount namespaces (privileged): a child in
    /// a fresh mount namespace opens a provider file and the drain still
    /// reports it (fd identity is namespace-independent).
    /// Run with `sudo -n` (fanotify needs `CAP_SYS_ADMIN`).
    #[test]
    #[ignore = "needs CAP_SYS_ADMIN fanotify group"]
    fn learn_live_drain_reports_opened_provider_across_mount_ns() {
        let dir = tempfile::tempdir().unwrap();
        let c = dir.path().join("livens.c");
        let so = dir.path().join("liblivens.so");
        std::fs::write(
            &c,
            "unsigned long C_GetFunctionList(void **out){ (void)out; return 5; }\n",
        )
        .unwrap();
        assert!(
            std::process::Command::new("gcc")
                .args(["-shared", "-fPIC", "-o"])
                .arg(&so)
                .arg(&c)
                .status()
                .unwrap()
                .success()
        );
        let (mut _learner, rx) = super::FileLearner::start().expect("fanotify group (run as root)");
        _learner.begin_drain().expect("spawn drain");
        let child = std::process::Command::new("unshare")
            .args(["-m", "cat"])
            .arg(&so)
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let mut got = None;
        while std::time::Instant::now() < deadline {
            match rx.recv_timeout(std::time::Duration::from_millis(200)) {
                Ok(super::LearnMsg::Candidate(candidate))
                    if candidate.display_path.ends_with("liblivens.so") =>
                {
                    got = Some(candidate);
                    break;
                }
                Ok(_) => continue,
                Err(_) => continue,
            }
        }
        let _ = child.wait_with_output();
        let candidate = got.expect("the drain reports the mount-ns open");
        assert!(
            candidate.loader_exe.is_some() || candidate.loader_unknown_reason.is_some(),
            "loader named or finitely unknown"
        );
        assert_ne!((candidate.dev, candidate.ino), (0, 0));
    }

    /// The per-file cache stays bounded: negatives may be forgotten under
    /// pressure (a re-check is just work), staged providers never are.
    #[test]
    fn learn_cache_stays_bounded() {
        let mut cache = super::LearnCache::new();
        for ino in 0..(super::LEARN_CACHE_CAP as u64 + 10) {
            let generation = (7, ino, 1024, 0, 0);
            if cache.needs_check(generation) {
                cache.note_decided(generation, false);
            }
        }
        assert!(
            cache.len() <= super::LEARN_CACHE_CAP,
            "negatives must not grow without bound: {}",
            cache.len()
        );
        assert!(cache.needs_check((7, 1, 1024, 0, 0)));
        cache.note_decided((7, 1, 1024, 0, 0), true);
        for ino in 100_000..(100_000 + super::LEARN_CACHE_CAP as u64 + 10) {
            let generation = (7, ino, 1024, 0, 0);
            if cache.needs_check(generation) {
                cache.note_decided(generation, false);
            }
        }
        assert_eq!(cache.decided_provider((7, 1, 1024, 0, 0)), Some(true));
    }
    /// Suffix-shared dynamic string tables: `PrefixC_GetFunctionList`
    /// stores the entry name mid-token. The pre-filter must let it
    /// through to the full parse (which then refuses it: no exact
    /// export), never refuse it as a certain negative.
    #[test]
    fn learn_prefilter_admits_suffix_shared_entry_names() {
        let dir = tempfile::tempdir().unwrap();
        let c = dir.path().join("suffix.c");
        let so = dir.path().join("libsuffix.so");
        std::fs::write(
            &c,
            "unsigned long PrefixC_GetFunctionList(void){return 1;}\n\
             unsigned long PrefixC_GetInterface(void){return 2;}\n\
             unsigned long PrefixC_GetInterfaceList(void){return 3;}\n",
        )
        .unwrap();
        assert!(
            std::process::Command::new("gcc")
                .args(["-shared", "-fPIC", "-o"])
                .arg(&so)
                .arg(&c)
                .status()
                .unwrap()
                .success()
        );
        let file = std::fs::File::open(&so).unwrap();
        assert!(
            super::elf_may_export_entry_points(&file).unwrap(),
            "a suffix-shared entry name must reach the full parse"
        );
        assert!(
            !super::check_elf_provider(&file).unwrap(),
            "the full parse is the authority: no exact entry-point export"
        );
    }

    /// A relocatable object is a certain negative even when it defines
    /// an entry-point symbol: it can never be loaded as a provider, and
    /// builds open thousands of them per minute.
    #[test]
    fn learn_prefilter_refuses_relocatable_objects() {
        let dir = tempfile::tempdir().unwrap();
        let c = dir.path().join("obj.c");
        let o = dir.path().join("obj.o");
        std::fs::write(
            &c,
            "unsigned long C_GetFunctionList(void **out){ (void)out; return 5; }\n",
        )
        .unwrap();
        assert!(
            std::process::Command::new("gcc")
                .args(["-c", "-o"])
                .arg(&o)
                .arg(&c)
                .status()
                .unwrap()
                .success()
        );
        let file = std::fs::File::open(&o).unwrap();
        assert!(
            !super::elf_may_export_entry_points(&file).unwrap(),
            "ET_REL is a certain negative"
        );
        assert!(!super::check_elf_provider(&file).unwrap());
    }

    /// The unread tail of an already-read buffer closes its fds: an
    /// early drain exit must not leak the event fds and pidfds the
    /// kernel installed for records past the break.
    #[test]
    fn learn_unread_tail_closes_event_and_pid_fds() {
        use std::os::unix::io::IntoRawFd;
        let tail_fd = std::fs::File::open("/bin/sh").unwrap().into_raw_fd();
        let tail_pidfd = std::fs::File::open("/bin/sh").unwrap().into_raw_fd();
        let mut buf = vec![0u8; 24 + 8];
        buf[0..4].copy_from_slice(&32u32.to_ne_bytes());
        buf[4] = 3;
        buf[6..8].copy_from_slice(&24u16.to_ne_bytes());
        buf[8..16].copy_from_slice(&0x20u64.to_ne_bytes());
        buf[16..20].copy_from_slice(&tail_fd.to_ne_bytes());
        buf[20..24].copy_from_slice(&1234i32.to_ne_bytes());
        buf[24] = 4;
        buf[26..28].copy_from_slice(&8u16.to_ne_bytes());
        buf[28..32].copy_from_slice(&tail_pidfd.to_ne_bytes());
        super::close_unread_tail(&buf, 0, buf.len());
        for fd in [tail_fd, tail_pidfd] {
            // SAFETY: fcntl probe on a just-closed fd number.
            let rc = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert_eq!(rc, -1, "tail fd {fd} must be closed");
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EBADF)
            );
        }
    }
}
