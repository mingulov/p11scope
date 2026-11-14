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

use std::collections::{BTreeSet, HashMap, HashSet};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::{Arc, Mutex};

/// Per-capture cap on staged learned files (spike C2 plan): beyond it the
/// engine refuses loudly with the aggregate cap gap, never silently.
pub(crate) const LEARNED_FILES_PER_CAPTURE_CAP: usize = 32;

/// Bound on the drain's per-file decision cache: negatives past the cap are
/// forgotten (a re-check is just work), staged providers never are. Sized
/// for a busy desktop's working set of distinct opened files (a build
/// tree, a mail store, a package cache): a cap below that set clears the
/// negatives every few thousand opens and turns every repeat open back
/// into a full check, which is what lets the finite kernel queue
/// overflow under ordinary churn. One entry is a 40-byte key plus a bool.
pub(crate) const LEARN_CACHE_CAP: usize = 65536;

/// Channel depth between the drain thread and the engine: the drain blocks
/// past it, so overload degrades to kernel queue overflow (a named gap),
/// never to silent loss.
const LEARN_CHANNEL_DEPTH: usize = 64;

/// Bound on learner workers that open mounts: the arming mark pass and
/// the end-of-capture drain join each wait at most this long. A hung
/// mount (unreachable NFS/CIFS, dead FUSE) must never wedge the start
/// before `capturing:` or the report at the end. On timeout the worker
/// is detached and the loss is reported so the engine files the named
/// overflow/unavailable gap.
const LEARN_WORKER_BOUND: std::time::Duration = std::time::Duration::from_secs(1);

/// Runs `work` on a named helper thread, waiting at most `bound` for
/// it: `Some` when it finishes in time, `None` on timeout (the helper
/// handle is dropped, which detaches the thread, so it finishes on
/// its own holding only its own fds — and the caller never blocks
/// past the bound), on spawn failure, or on panic. The arming mark
/// pass uses this so a hung mount cannot wedge the start; the end
/// join applies the same bound through the drain's done channel below.
fn run_with_bound<T: Send + 'static>(
    name: &str,
    bound: std::time::Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    let helper = std::thread::Builder::new()
        .name(name.to_string())
        .spawn(move || {
            let _ = tx.send(work());
        });
    let helper = match helper {
        Ok(helper) => helper,
        Err(_) => return None,
    };
    match rx.recv_timeout(bound) {
        Ok(value) => {
            let _ = helper.join();
            Some(value)
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            let _ = helper.join();
            None
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            // Dropping the handle detaches the helper; forgetting it
            // would leave the thread joinable (leaked) instead.
            drop(helper);
            None
        }
    }
}

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
#[cfg(test)]
pub(crate) fn check_elf_provider(file: &std::fs::File) -> Result<bool, String> {
    Ok(prove_with_loader(file, || (None, None))?.is_some())
}

/// A loader's program, or the finite reason it is unknown.
type LoaderNaming = (Option<String>, Option<&'static str>);

/// The provider test with loader naming in the middle: the cheap byte
/// tests (file type, ELF magic, the export-name prefilter) run first, so
/// the overwhelming majority of opens — data files, non-provider
/// libraries — are refused without touching procfs; only an ELF that may
/// export an entry point names its loader, and it does so before the
/// full export parse spends time a one-shot loader does not have.
/// `Ok(None)` is a certain negative; `Ok(Some(loader))` a proved provider
/// with whatever `name_loader` returned; `Err` an I/O failure the caller
/// must not cache.
fn prove_with_loader(
    file: &std::fs::File,
    name_loader: impl FnOnce() -> LoaderNaming,
) -> Result<Option<LoaderNaming>, String> {
    use std::os::unix::fs::FileExt;
    let file_type = file
        .metadata()
        .map_err(|error| format!("metadata failed: {error}"))?
        .file_type();
    if !file_type.is_file() {
        return Ok(None);
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
        return Ok(None);
    }
    if !elf_may_export_entry_points(file)? {
        return Ok(None);
    }
    let loader = name_loader();
    let inspected = p11scope_manifest::identity::inspect_file_with_reader_exporting(
        file,
        |file, bytes, offset| file.read_at(bytes, offset),
        &crate::discovery::scan::standard_function_names(),
    )
    .map_err(|error| format!("identify failed: {error}"))?;
    Ok(exports_entry_point(&inspected.exports).then_some(loader))
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
/// `autofs` is skipped as well: opening the trigger would mount (and,
/// re-opened every 30 s, keep mounted) NAS shares, and a dead server
/// would hang the pass. A share already mounted still shows through
/// its own real filesystem entry, which is marked.
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
    "devtmpfs",
    "sockfs",
    "pipefs",
    "anon_inodefs",
    "autofs",
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

/// One mark attempt: the mount the held open resolved to, and the
/// mount actually marked when the syscall succeeded. A failed add
/// keeps its resolved identity so the evaluator can credit a path
/// that still reaches an already-marked filesystem (an unchanged
/// shadow after the capability shed) instead of filing a false gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MarkOutcome {
    resolved: Option<MountIdentity>,
    marked: Option<MountIdentity>,
}

/// Mounts to mark, parsed from `/proc/self/mountinfo` text: field 1
/// is the mount id, field 3 the filesystem device, field 5 the mount
/// point, and the field after `" - "` is the fstype. Malformed lines
/// are skipped; escapes (`\040` etc.) are decoded. Paths stay
/// byte-exact (`PathBuf`): a lossy string could miss a mark. A point
/// mounted over keeps the last (topmost) entry, which is where the
/// path resolves — and a pseudo overmount (an `autofs` trigger over a
/// real path) removes the lower same-path locator instead of leaving
/// it behind: overmount replacement wins over the pseudo skip, so the
/// hidden path never reaches the mark pass. Real entries mounted
/// later at descendant paths are still visible and are kept; entries
/// the trigger already hides are dropped with the lower mount.
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
        let point = unescape_mountinfo(fields[4]);
        if point.as_os_str().is_empty() {
            continue;
        }
        if PSEUDO_FS.contains(&fields[sep + 1]) {
            // What the trigger covers is hidden: drop the lower
            // same-path locator and any descendant locators mounted
            // before it, so neither reaches the mark pass (opening
            // such a path would open the trigger). Marking through a
            // real cover is harmless — the mark lands on the coverer
            // and is credited there — but an `autofs` trigger must
            // never be opened at all.
            mounts.retain(|mount| !mount.point.starts_with(&point));
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

/// Counts the parseable records at the buffer start: pure
/// length-field walking, no fd touched. Stops at the first malformed
/// record. The tail and the shed owe events, not bytes, so this is
/// what their snapshots are accounted against.
fn count_parsed_records(buf: &[u8]) -> usize {
    let mut count = 0usize;
    let mut offset = 0usize;
    while offset < buf.len() {
        match parse_fanotify_event(&buf[offset..]) {
            Ok(event) => {
                count += 1;
                offset += event.total_len;
            }
            Err(_) => break,
        }
    }
    count
}

/// Sets `FD_CLOEXEC` explicitly on a kernel-handed fd: the group is
/// created with `FAN_CLOEXEC`, but event and pid fds must not rely on
/// propagation through the observer's own `Command::spawn`s (the
/// discover helper) on every supported kernel. One syscall:
/// `FD_CLOEXEC` is the only fd flag, so no read-modify-write is needed.
fn set_cloexec(fd: std::os::unix::io::RawFd) {
    // SAFETY: fcntl on a live owned fd; failure only loses the flag.
    unsafe {
        libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC);
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
/// read happens mid-proof: after the cheap byte tests admit the file,
/// before the full export parse. A loader
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

/// Runs the arming mark pass on a bounded helper: `Some` with the
/// marked group when it finishes in time, `None` on timeout. On
/// timeout the helper is detached holding the group, so the owner
/// stops its further marks through a shared cancel flag and removes
/// the marks it already placed: a duplicate of the group names the
/// same group, and flushing the filesystem marks through it (the
/// startup `CAP_SYS_ADMIN` grant is still held here) plus draining
/// the events queued before the flush down to `EAGAIN` (closing their
/// fds, releasing their mount pins) leaves the detached group with
/// nothing queued behind it — no unbounded kernel queue, no pinned
/// mounts — before the duplicate is closed. The `mark` closure
/// receives the group and the cancel flag; production marks every
/// visible filesystem, tests inject a stalled pass.
fn arm_with_bound(
    group: OwnedFd,
    mark: impl FnOnce(&OwnedFd, &AtomicBool) -> (BTreeSet<MountIdentity>, usize) + Send + 'static,
) -> Option<(OwnedFd, BTreeSet<MountIdentity>, usize)> {
    let dup = group.try_clone().ok();
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel_helper = Arc::clone(&cancel);
    let pass = run_with_bound("p11scope-learn-mark", LEARN_WORKER_BOUND, move || {
        let (covered, uncovered) = mark(&group, &cancel_helper);
        (group, covered, uncovered)
    });
    let Some(result) = pass else {
        cancel.store(true, Ordering::Release);
        if let Some(dup) = dup {
            flush_filesystem_marks(dup.as_raw_fd());
            drain_group_closing_to_eagain(dup.as_raw_fd());
        }
        return None;
    };
    drop(dup);
    Some(result)
}

/// Reads a group down to `EAGAIN`, closing every event's fds: after
/// the arming-timeout flush, the events queued before the flush still
/// pin their mounts until the hung helper exits — draining them
/// through the duplicate releases the pins now instead of waiting.
/// The group is non-blocking, so an empty queue ends the drain. A read
/// error other than `EAGAIN`/`EINTR` (a device-node `EBUSY`, whose head
/// was consumed) continues past the head instead of pinning the rest of
/// the queue behind it, bounded so a persistently failing fd cannot
/// spin forever.
fn drain_group_closing_to_eagain(raw: std::os::unix::io::RawFd) {
    let mut buf = [0u8; 64 * 1024];
    let mut consecutive_errors = 0usize;
    loop {
        // SAFETY: libc read into a live buffer; NONBLOCK so no stall.
        let got = unsafe { libc::read(raw, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if got < 0 {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(errno) if errno == libc::EINTR => continue,
                Some(errno) if errno == libc::EAGAIN => return,
                _ => {
                    consecutive_errors = consecutive_errors.saturating_add(1);
                    if consecutive_errors > 1024 {
                        return;
                    }
                    continue;
                }
            }
        }
        consecutive_errors = 0;
        if got == 0 {
            return;
        }
        close_unread_tail(&buf, 0, got as usize);
    }
}

/// The drain thread with its exit signal: the handle joins only after
/// the done channel fires (or breaks on panic), so the end join can
/// wait with the worker bound and detach a hung drain instead of
/// hanging the report. Bundled so a thread never exists without its
/// signal.
struct LearnerThread {
    handle: std::thread::JoinHandle<()>,
    done: Receiver<()>,
}

/// The drain thread handle, owned by the engine. Drop signals shutdown and
/// joins bounded (a hung drain is detached at the worker bound, never
/// waited on past it).
pub(crate) struct FileLearner {
    state: Arc<LearnShutdownState>,
    thread: Option<LearnerThread>,
    /// The armed learner held between arming and `begin_drain`: the
    /// reader thread spawns post-shed so it never retains the transient
    /// startup `CAP_SYS_ADMIN` (capabilities are per-thread). `None`
    /// once the drain runs.
    pending: Option<PendingArming>,
}

/// The armed learner between `start()` and `begin_drain`: the group,
/// the drain channel, the startup mark coverage, whether the startup
/// pass left a visible filesystem uncovered (filed as the finite
/// unavailable-learning gap once the drain runs), this kernel's
/// measured `FIONREAD` bytes per event (which the drain's tail and
/// shed divide their snapshots by), and whether that unit was exactly
/// measured (`true`) or fell back (`false`).
struct PendingArming {
    group: OwnedFd,
    tx: SyncSender<LearnMsg>,
    covered: BTreeSet<MountIdentity>,
    initial_gap_owed: bool,
    fionread_unit: usize,
    fionread_exact: bool,
}

/// Opens the fanotify group for learning: the kernel queue is
/// unlimited (`FAN_UNLIMITED_QUEUE`, which the startup grant allows)
/// so the events queued between arming and the post-shed drain start
/// — the whole BPF setup — and short bursts never overflow the
/// default 16384-event queue on a busy host. A kernel that refuses
/// the flag falls back to the finite queue, whose overflow is the
/// same named gap.
fn open_learn_group() -> Result<OwnedFd, LearnAbsent> {
    let flags =
        libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK | libc::FAN_REPORT_PIDFD;
    // `O_CLOEXEC` in the event flags makes the kernel install every
    // event fd close-on-exec at read time (pidfds always are), so
    // the hot path needs no extra fcntl. `O_NONBLOCK` keeps the
    // read itself from blocking: the kernel opens each event's file
    // inside `read(2)`, and a FIFO opened read-only without it
    // waits for a writer, stalling the whole drain until one comes.
    let event_flags = libc::O_RDONLY as u32
        | libc::O_LARGEFILE as u32
        | libc::O_CLOEXEC as u32
        | libc::O_NONBLOCK as u32;
    // SAFETY: libc call with flag constants only; the return is
    // checked before any use.
    let mut fd = unsafe { libc::fanotify_init(flags | libc::FAN_UNLIMITED_QUEUE, event_flags) };
    if fd < 0 {
        // SAFETY: as above.
        fd = unsafe { libc::fanotify_init(flags, event_flags) };
    }
    if fd < 0 {
        return Err(LearnAbsent {
            reason: format!("fanotify_init failed: {}", std::io::Error::last_os_error()),
        });
    }
    // SAFETY: fanotify_init returned an owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

impl FileLearner {
    /// Opens the fanotify group and marks every real filesystem
    /// (both need the startup `CAP_SYS_ADMIN` grant), but does not
    /// spawn the reader: call `begin_drain` after the post-setup
    /// capability shed. Without the grant (or fanotify at all) this
    /// returns `LearnAbsent` and the capture keeps today's gaps,
    /// never a fatal.
    pub(crate) fn start() -> Result<(Self, Receiver<LearnMsg>), LearnAbsent> {
        // The bound moves to user space: the drain sheds a backlog
        // past `LEARN_BACKLOG_CAP_BYTES` as a named overflow, and no
        // drain step blocks on a mount.
        let group = open_learn_group()?;
        // The FIONREAD unit before any filesystem mark exists: the
        // probe inode is the only marked object, so one open queues
        // exactly one event and the snapshot is the unit.
        let (fionread_unit, fionread_exact) = measure_fionread_unit(&group);
        // The mark pass opens every visible mount: on a hung mount
        // (unreachable NFS/CIFS, dead FUSE) an open can block
        // indefinitely, which would wedge `--system` start before
        // `capturing:`. Run it on a helper under the worker bound; on
        // timeout the helper is detached (its marks are flushed
        // through a duplicate while the startup grant is still held,
        // it places no further marks once cancelled, and it closes
        // the group when the hang clears) and learning is unavailable
        // — a named gap, never a hung start.
        let pass = arm_with_bound(group, |group, cancel| {
            mark_visible_filesystems(group, &BTreeSet::new(), cancel)
        });
        let Some((group, covered, uncovered)) = pass else {
            return Err(LearnAbsent {
                reason: "mark pass did not finish within the hung-mount bound".to_string(),
            });
        };
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
                "p11scope: file learning active: {} filesystems marked ({uncovered} skipped), FIONREAD unit {fionread_unit} B/event",
                covered.len()
            );
        }
        let (tx, rx) = std::sync::mpsc::sync_channel(LEARN_CHANNEL_DEPTH);
        let state = Arc::new(LearnShutdownState::default());
        Ok((
            Self {
                state,
                thread: None,
                pending: Some(PendingArming {
                    group,
                    tx,
                    covered,
                    initial_gap_owed: uncovered > 0,
                    fionread_unit,
                    fionread_exact,
                }),
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
        let Some(arming) = self.pending.take() else {
            return Ok(());
        };
        let worker_state = Arc::clone(&self.state);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        match std::thread::Builder::new()
            .name("p11scope-learn".to_string())
            .spawn(move || {
                drain_loop(
                    arming.group,
                    arming.tx,
                    worker_state,
                    arming.covered,
                    arming.initial_gap_owed,
                    arming.fionread_unit,
                    arming.fionread_exact,
                );
                let _ = done_tx.send(());
            }) {
            Ok(thread) => {
                self.thread = Some(LearnerThread {
                    handle: thread,
                    done: done_rx,
                });
                Ok(())
            }
            Err(error) => Err(LearnAbsent {
                reason: format!("learn thread spawn failed: {error}"),
            }),
        }
    }

    /// Stops the drain and joins it, reporting whether a tail was lost:
    /// an unsent message or unread queue contents at shutdown, a drain
    /// thread that panicked, or a join that hit the worker bound. A
    /// drain stuck in a hung mark open (hard NFS, dead FUSE) is
    /// detached at the bound — its handle is dropped, holding only its
    /// own fds and sender, exiting on its own once the hang clears —
    /// and counts as lost. The engine files that loss loudly (the
    /// overflow aggregate). Bounded: the report is never blocked.
    pub(crate) fn shutdown_and_join(&mut self) -> bool {
        self.shutdown_and_join_pumping(|| {})
    }

    /// `shutdown_and_join` with the engine's channel pump: the drain
    /// decides the events queued at the stop and may send their
    /// candidates and load tallies, so the caller keeps receiving
    /// (`pump`) while it waits for the drain to exit, instead of
    /// leaving those sends stuck behind a full channel.
    pub(crate) fn shutdown_and_join_pumping(&mut self, mut pump: impl FnMut()) -> bool {
        self.state.shutdown.store(true, Ordering::Release);
        // Record when the stop landed (first stop wins): the tail
        // deadline anchors to it, so the tail fits inside the join
        // bound however late the drain notices the stop.
        if let Ok(mut stop) = self.state.stop.lock()
            && stop.is_none()
        {
            *stop = Some(std::time::Instant::now());
        }
        // A never-begun learner holds the only sender: drop it so the
        // channel closes terminally instead of dangling.
        self.pending = None;
        let mut lost = self.state.lost_tail.load(Ordering::Acquire);
        let mut had_thread = false;
        if let Some(worker) = self.thread.take() {
            had_thread = true;
            // A panic breaks the channel (the sender drops unsent), so
            // a disconnect also means the thread is gone and the join
            // below reaps it without blocking.
            let deadline = std::time::Instant::now() + LEARN_WORKER_BOUND;
            let exited = loop {
                pump();
                let now = std::time::Instant::now();
                if now >= deadline {
                    break false;
                }
                let step = (deadline - now).min(std::time::Duration::from_millis(5));
                match worker.done.recv_timeout(step) {
                    Ok(()) | Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break true,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                }
            };
            if exited {
                if worker.handle.join().is_err() {
                    self.state.note_unexpected_exit_once();
                    lost = true;
                }
            } else {
                // Dropping the handle detaches the drain; forgetting
                // it would leave the thread joinable (leaked) instead.
                // The timeout itself is a loss source, counted here:
                // the detached drain may never exit to count it.
                drop(worker.handle);
                self.state.loss_join_timeout.fetch_add(1, Ordering::Relaxed);
                lost = true;
            }
        }
        // The final learner line, after the join so post-drain bumps
        // (panic, join timeout) appear on it. The drain stored its last
        // counters at every tick and at exit; a drain that never ran
        // prints nothing.
        if had_thread && crate::run::capture_diagnostics_on() {
            print_final_telemetry(&self.state);
        }
        lost || self.state.lost_tail.load(Ordering::Acquire)
    }

    /// Attributes the engine's unexpected-disconnect path to the `other`
    /// telemetry counter, once per learner together with the join panic:
    /// both observe the same drain death, but the next
    /// `learned_event_loss` traces to a single source.
    pub(crate) fn note_other_loss(&self) {
        self.state.note_unexpected_exit_once();
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
/// from an earlier pass on the *same mount identity*, or when the
/// failed add resolved to an already-marked identity (an unchanged
/// shadow after the capability shed: the startup mark on the
/// resolving mount survives the shed and keeps delivering). A
/// failure that resolved to an unmarked identity, or never resolved
/// at all, counts as uncovered. The next covered set retains exactly
/// the mounts actually marked plus the retained snapshot mounts
/// still visible — never a shadowed snapshot identity, so a
/// shadowing mount that goes away leaves the reappeared snapshot
/// honestly uncovered. A remount or a replacement filesystem at an
/// already covered path carries a new mount id, so it never inherits
/// the dead mount's coverage. Coverage therefore comes from this
/// retained-identity set alone — traffic on older filesystems can
/// never stand in for a filesystem whose mark failed. Returns the
/// next covered set and the uncovered-visible count; a nonzero
/// count owes the finite unavailable-learning gap.
pub(crate) fn evaluate_mark_coverage(
    previously_covered: &BTreeSet<MountIdentity>,
    visible: &[MountToMark],
    mut mark: impl FnMut(&std::path::Path) -> MarkOutcome,
) -> (BTreeSet<MountIdentity>, usize) {
    // Each entry is judged by its own mark outcome alone, so one
    // pass over the snapshot cannot credit the wrong mount however
    // the table is ordered. The callback reports the mount the held
    // open resolved to alongside the mount actually marked, both
    // derived from the held descriptor — never the snapshot's
    // say-so. A successful mark covers its path even when the open
    // resolved to a different mount than the snapshot; a failed add
    // covers its path only when it resolved to an already-marked
    // identity, whether retained from an earlier pass or marked
    // earlier in this same pass.
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
        let outcome = mark(&mount.point);
        if let Some(marked) = outcome.marked
            && covered.len() < MARK_COVERAGE_CAP
        {
            covered.insert(marked);
            continue;
        }
        if outcome.marked.is_none()
            && let Some(resolved) = outcome.resolved
            && covered.len() < MARK_COVERAGE_CAP
            && (previously_covered.contains(&resolved) || covered.contains(&resolved))
        {
            covered.insert(resolved);
            continue;
        }
        uncovered += 1;
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
/// `FAN_MARK_FILESYSTEM` through an `O_PATH` fd with `EBADF` —
/// probed, not just read from the man page — so `O_PATH` cannot
/// carry the mark even though it would avoid automount triggers).
/// Automount triggers are avoided by skipping the `autofs` fstype
/// instead: the trigger is never opened at all. `O_DIRECTORY |
/// O_NOFOLLOW` bind the handle to the directory itself, so the mark
/// and its identity credit cannot slide onto a non-directory or
/// through a trailing symlink. `None` (an unopenable mount point) is
/// a named gap, never silent coverage.
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

/// Opens a file bind mount for a filesystem mark. The type is probed
/// first through an `O_PATH | O_NOFOLLOW | O_CLOEXEC` fd, which never
/// opens the object itself (no device side effects, no automount
/// trigger — open(2)): only a regular file proceeds. A device bind
/// (`/dev/watchdog`, a tty), fifo, socket or symlink is never opened
/// `O_RDONLY` — opening a watchdog arms it, opening a tty without
/// `O_NOCTTY` can take a controlling terminal — and is skipped
/// instead (the uncovered count files the named gap, never silent
/// coverage). The read-only handle reopens the type-checked probe
/// through its own `/proc/self/fd/N` link and never re-resolves the
/// pathname, so an ancestor swapped for a device between the probe
/// and the open cannot redirect it: a device is never opened, not
/// merely refused afterwards. The handle carries `O_NONBLOCK` and
/// `O_NOCTTY`, never `O_PATH` (the kernel rejects
/// `FAN_MARK_FILESYSTEM` through an `O_PATH` fd with `EBADF`) and
/// never `O_DIRECTORY` (a file bind refuses it with `ENOTDIR`); it
/// carries no `O_NOFOLLOW` because the fd link resolves to the held
/// object itself (`O_NOFOLLOW` would refuse that link with `ELOOP`) —
/// symlink refusal lives at the probe, which stats a symlink as
/// `S_IFLNK`. The final fd is re-statted and identity-checked
/// against the probe, so it is provably the same regular file. The
/// mark covers the file's filesystem — the same superblock its own
/// mount entry marks — so the bind needs no separate filesystem of
/// its own.
fn open_file_for_mark(point: &std::path::Path) -> Option<OwnedFd> {
    open_file_for_mark_impl(point, || {}, |_| {})
}

/// Test seam: `on_readable_open` observes the file type (`S_IFMT` bits)
/// of every successful read-only reopen, including opens the final
/// identity check later refuses, so the device-safety tests prove a
/// device is never opened — not merely refused afterwards. A failed
/// post-open fstat reports `0` (unknown type, fail-closed). Production
/// passes a no-op.
#[cfg(test)]
fn open_file_for_mark_with_readable_observer(
    point: &std::path::Path,
    on_readable_open: impl FnMut(u32),
) -> Option<OwnedFd> {
    open_file_for_mark_impl(point, || {}, on_readable_open)
}

/// Test seam combining both hooks for the ancestor-swap twin.
#[cfg(test)]
fn open_file_for_mark_with_hooks(
    point: &std::path::Path,
    pre_reopen: impl FnOnce(),
    on_readable_open: impl FnMut(u32),
) -> Option<OwnedFd> {
    open_file_for_mark_impl(point, pre_reopen, on_readable_open)
}

fn open_file_for_mark_impl(
    point: &std::path::Path,
    pre_reopen: impl FnOnce(),
    mut on_readable_open: impl FnMut(u32),
) -> Option<OwnedFd> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(point.as_os_str().as_bytes()).ok()?;
    // SAFETY: libc call; the NUL-terminated path is valid.
    let probe = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if probe < 0 {
        return None;
    }
    // SAFETY: `probe` is a fresh owned descriptor from the open above.
    let probe = unsafe { OwnedFd::from_raw_fd(probe) };
    // SAFETY: fstat on our own held descriptor into a zeroed stat.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(probe.as_raw_fd(), &mut stat) } != 0 {
        return None;
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return None;
    }
    let (probed_dev, probed_ino) = (stat.st_dev, stat.st_ino);
    pre_reopen();
    // The type-checked descriptor itself is the open path: the
    // read-only handle reopens the held probe through its own
    // `/proc/self/fd/N` link, following the repo's held-FD practice,
    // and never re-resolves the original pathname — an ancestor
    // replaced in between cannot redirect it onto a device. No
    // `O_NOFOLLOW` here: the fd link is traversed by the kernel to
    // the held object itself, and `O_NOFOLLOW` would refuse it with
    // `ELOOP` (probed, not just read from the man page).
    let fd_path = std::ffi::CString::new(format!("/proc/self/fd/{}", probe.as_raw_fd())).ok()?;
    // SAFETY: libc call; the NUL-terminated fd link is valid, and the
    // probe is alive for this whole call so the link cannot dangle.
    let raw = unsafe {
        libc::open(
            fd_path.as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return None;
    }
    // SAFETY: `raw` is a fresh owned descriptor from the open above.
    let held = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: fstat on our own held descriptor into a zeroed stat.
    let mut final_stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(held.as_raw_fd(), &mut final_stat) } != 0 {
        on_readable_open(0);
        return None;
    }
    on_readable_open(final_stat.st_mode & libc::S_IFMT);
    if final_stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || (final_stat.st_dev, final_stat.st_ino) != (probed_dev, probed_ino)
    {
        return None;
    }
    Some(held)
}

/// Adds one filesystem mark through a held descriptor for the
/// mount point (the NULL-pathname fd form), returning the mount the
/// held open resolved to alongside the mount actually marked, both
/// read from that same descriptor against the pass snapshot.
/// Directories mark through the directory handle; file bind mounts
/// (a file where the snapshot shows a mount point) mark through a
/// file handle, covering the file's filesystem. The resolved
/// identity is reported even when the kernel refuses the add (for
/// example without `CAP_SYS_ADMIN` after the capability shed), so a
/// path that still reaches an already-marked filesystem stays
/// covered; an unresolvable open (for example an `O_RDONLY` open
/// refused with `EACCES`) or an unreadable identity marks nothing
/// and resolves to nothing: an uncredited mark is a named gap,
/// never silent coverage. Marking the held object — not re-resolving
/// the pathname inside the syscall — is what binds the credit to
/// the mount actually marked when an overmount races the mountinfo
/// snapshot.
fn try_mark_filesystem(
    group: &OwnedFd,
    point: &std::path::Path,
    mounts: &[MountToMark],
) -> MarkOutcome {
    try_mark_filesystem_with(point, mounts, |held| {
        // SAFETY: libc call; the group and held descriptors are valid,
        // and a NULL pathname marks the held descriptor's object.
        0 == unsafe {
            libc::fanotify_mark(
                group.as_raw_fd(),
                libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
                libc::FAN_OPEN,
                held,
                std::ptr::null(),
            )
        }
    })
}

/// The periodic re-mark's mark step over the shared group: locks it
/// only around the `fanotify_mark` call, so a helper hung in a mount
/// open holds no group reference. After drain exit took the group,
/// every mark is refused (that pass result is unadopted anyway).
/// Poison is benign: the guarded value carries no invariant, so a
/// panicked helper never wedges a later pass.
fn try_mark_filesystem_shared(
    shared: &Arc<Mutex<Option<OwnedFd>>>,
    point: &std::path::Path,
    mounts: &[MountToMark],
) -> MarkOutcome {
    try_mark_filesystem_with(point, mounts, |held| {
        let guard = shared
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(group) = guard.as_ref() else {
            return false;
        };
        // SAFETY: as above; the guard keeps the group alive across it.
        0 == unsafe {
            libc::fanotify_mark(
                group.as_raw_fd(),
                libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
                libc::FAN_OPEN,
                held,
                std::ptr::null(),
            )
        }
    })
}

/// Marks one mount point's filesystem through a held descriptor (see
/// `try_mark_filesystem`): opens and resolves first, then marks
/// through `mark`, which receives the held descriptor and reports
/// whether the kernel took the mark.
fn try_mark_filesystem_with(
    point: &std::path::Path,
    mounts: &[MountToMark],
    mark: impl FnOnce(std::os::unix::io::RawFd) -> bool,
) -> MarkOutcome {
    let Some(held) = open_mount_for_mark(point).or_else(|| open_file_for_mark(point)) else {
        return MarkOutcome {
            resolved: None,
            marked: None,
        };
    };
    let resolved = mount_identity_of_fd(&held, mounts);
    let marked = if mark(held.as_raw_fd()) {
        resolved
    } else {
        None
    };
    MarkOutcome { resolved, marked }
}

/// One (re-)mark pass over the visible filesystems, retaining the
/// coverage earlier passes established. Returns the next covered set
/// and how many visible filesystems it leaves uncovered. `cancel` is
/// checked before each mark: a cancelled pass places no further marks
/// (a mount it already passed keeps its mark; a mount it never reached
/// stays uncovered), so a detached arming helper stops dirtying the
/// group once the owner gives up on it.
fn mark_visible_filesystems(
    group: &OwnedFd,
    previously_covered: &BTreeSet<MountIdentity>,
    cancel: &AtomicBool,
) -> (BTreeSet<MountIdentity>, usize) {
    let mounts = visible_mounts();
    evaluate_mark_coverage(previously_covered, &mounts, |point| {
        if cancel.load(Ordering::Acquire) {
            return MarkOutcome {
                resolved: None,
                marked: None,
            };
        }
        try_mark_filesystem(group, point, &mounts)
    })
}

/// One periodic re-mark pass over the visible filesystems through the
/// shared group, retaining the coverage earlier passes established.
/// Returns the next covered set and how many visible filesystems it
/// leaves uncovered. Never cancelled: the helper runs to completion
/// (locking the group only around each mark), and drain exit takes
/// the group instead of waiting for it.
fn mark_visible_filesystems_shared(
    shared: &Arc<Mutex<Option<OwnedFd>>>,
    previously_covered: &BTreeSet<MountIdentity>,
) -> (BTreeSet<MountIdentity>, usize) {
    let mounts = visible_mounts();
    evaluate_mark_coverage(previously_covered, &mounts, |point| {
        try_mark_filesystem_shared(shared, point, &mounts)
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
/// dropping it silently at the boundary, and `stop` records when the
/// stop landed so the tail deadline is anchored to the stop — not to
/// whenever the drain notices it — and always fits inside the join
/// bound. The `loss_*` counters attribute every learning loss to its
/// source for the `-v` telemetry line: counts only, never paths, pids
/// or file bytes. `other` covers the residual sources — parse errors,
/// `FIONREAD` failures, drain exits after failed sends or poll errors,
/// drain panics, and engine disconnects — so the next
/// `learned_event_loss` can be traced. `final_stats` carries the
/// drain's last counters to the join for the final telemetry line (the
/// drain stores at every tick and at exit; the join prints after
/// reaping, so post-drain bumps appear). `unexpected_exit_filed` makes
/// the panic/disconnect `other` bump once-only: both the join and the
/// engine observe the same death, but the telemetry counts it once.
#[derive(Debug, Default)]
struct LearnShutdownState {
    shutdown: AtomicBool,
    lost_tail: AtomicBool,
    stop: std::sync::Mutex<Option<std::time::Instant>>,
    loss_shed: std::sync::atomic::AtomicU64,
    loss_tail_deadline: std::sync::atomic::AtomicU64,
    loss_read_error: std::sync::atomic::AtomicU64,
    loss_send_deadline: std::sync::atomic::AtomicU64,
    loss_join_timeout: std::sync::atomic::AtomicU64,
    loss_other: std::sync::atomic::AtomicU64,
    final_stats: std::sync::Mutex<DrainStats>,
    unexpected_exit_filed: AtomicBool,
}

impl LearnShutdownState {
    /// Attributes one unexpected drain death (panic or disconnect) to
    /// `other`, once per learner: the join and the engine both observe
    /// the same death, but only the first files it.
    fn note_unexpected_exit_once(&self) {
        if !self.unexpected_exit_filed.swap(true, Ordering::AcqRel) {
            self.loss_other.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Sends one message, waiting past a full channel in 1 ms steps so a
/// shutdown (or a dropped receiver) always breaks the wait within the
/// tail bound: a blocking send here could wedge the engine's drop on a
/// full channel. Returns false when the drain must exit; a message
/// still unsent at the bound marks the lost tail.
fn send_learn(tx: &SyncSender<LearnMsg>, state: &Arc<LearnShutdownState>, msg: LearnMsg) -> bool {
    send_learn_in(tx, state, msg, SendWindow::Live)
}

/// When a send may still wait for channel room: during the capture
/// until shutdown, during the end-of-capture tail drain until its
/// deadline (the engine pumps the channel while it waits for the join).
#[derive(Clone, Copy)]
enum SendWindow {
    Live,
    Final(std::time::Instant),
}

fn send_learn_in(
    tx: &SyncSender<LearnMsg>,
    state: &Arc<LearnShutdownState>,
    mut msg: LearnMsg,
    mut window: SendWindow,
) -> bool {
    loop {
        // A live send caught by the stop keeps its message: the engine
        // pumps the channel while it waits for the join, so the send
        // gets the tail drain's bound — anchored to the stop, like the
        // tail itself — instead of dropping at once.
        if matches!(window, SendWindow::Live) && state.shutdown.load(Ordering::Acquire) {
            window = SendWindow::Final(tail_deadline_from(state));
        }
        let closed = match window {
            SendWindow::Live => false,
            SendWindow::Final(deadline) => std::time::Instant::now() >= deadline,
        };
        if closed {
            state.lost_tail.store(true, Ordering::Release);
            state.loss_send_deadline.fetch_add(1, Ordering::Relaxed);
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

/// How long the end-of-capture tail drain may run: it must finish
/// inside the engine's join bound, so a tail it cannot finish is
/// reported as lost before the join gives up on the thread.
const FINAL_DRAIN_BOUND: std::time::Duration = std::time::Duration::from_millis(750);

/// The end-of-capture tail deadline: the recorded stop instant plus
/// the final drain bound, so the tail fits inside the engine's join
/// bound however late the drain notices the stop. Falls back to now
/// plus the bound when no stop was recorded (a bare tail drain in
/// tests) or the lock is poisoned.
fn tail_deadline_from(state: &LearnShutdownState) -> std::time::Instant {
    let stop = state.stop.lock().ok().and_then(|guard| *guard);
    stop.map(|at| at + FINAL_DRAIN_BOUND)
        .unwrap_or_else(|| std::time::Instant::now() + FINAL_DRAIN_BOUND)
}

/// Drain counters for the periodic `-v` telemetry line: counts only,
/// never paths, pids or file bytes.
#[derive(Default, Clone, Copy, Debug)]
struct DrainStats {
    events: u64,
    checked: u64,
    proved: u64,
    sent_candidates: u64,
    sent_loads: u64,
    overflows: u64,
    unreadable: u64,
}

/// The drain's per-event state: the decision cache, the counters and
/// the channel to the engine.
struct DrainCtx<'a> {
    group: std::os::unix::io::RawFd,
    tx: &'a SyncSender<LearnMsg>,
    state: &'a Arc<LearnShutdownState>,
    self_pid: u32,
    /// This kernel's `FIONREAD` bytes per event, measured once in
    /// `start()`: the tail and the shed owe `snapshot / unit` events.
    /// 24 before upstream `68615158c12d`, 32 after.
    fionread_unit: usize,
    /// Whether the unit above was exactly measured (`true`) or fell back
    /// to the header (`false`): with an exact unit the snapshot divides
    /// evenly, so leftover owed with an empty queue is a lease-blocked
    /// head, not over-count.
    fionread_exact: bool,
    cache: LearnCache,
    stats: DrainStats,
    /// Inode ignore marks placed so far (bounded by
    /// `LEARN_IGNORE_MARK_CAP`).
    ignore_marks: usize,
    /// Generations already ignore-marked since the last flush: each is
    /// marked at most once per flush period, so the counter above
    /// counts live marks, not mark calls.
    marked_this_period: HashSet<FileGeneration>,
}

/// Bound on the kernel-side ignore marks the drain places on files it
/// proved negative: the marks count against the user's fanotify mark
/// limit, which other root watchers share. Past the cap repeat opens
/// are still decided through the user-space cache, only without the
/// kernel filter.
const LEARN_IGNORE_MARK_CAP: usize = 16384;

/// Asks the kernel to stop queueing opens of one file the drain proved
/// is not a provider: an inode ignore mark (`FAN_MARK_IGNORED_MASK`)
/// suppresses the filesystem mark's `FAN_OPEN` for exactly that inode.
/// Without `FAN_MARK_IGNORED_SURV_MODIFY` the kernel clears the ignore
/// on the file's next modification, so rewritten bytes are re-proved on
/// their next open. The mark is evictable (`FAN_MARK_EVICTABLE`): it
/// never pins the inode, and an evicted inode simply reports its next
/// open again. Repeat opens of the same files dominate a busy
/// host's open traffic (shared libraries of every exec, build inputs,
/// mail and package stores); filtering them in the kernel is what keeps
/// the finite queue from overflowing under ordinary churn. Best effort:
/// a refused mark (mark limit, permission) leaves the user-space cache
/// deciding repeat opens as before.
fn ignore_negative_inode(group: std::os::unix::io::RawFd, file: &std::fs::File) -> bool {
    // SAFETY: libc call; the group and the held event fd are valid,
    // and a NULL pathname marks the held fd's inode.
    let rc = unsafe {
        libc::fanotify_mark(
            group,
            libc::FAN_MARK_ADD | libc::FAN_MARK_IGNORED_MASK | libc::FAN_MARK_EVICTABLE,
            libc::FAN_OPEN,
            file.as_raw_fd(),
            std::ptr::null(),
        )
    };
    rc == 0
}

/// Removes one file's inode ignore mark again: the undo for a mark
/// that raced a writer between the proof reads and the mark syscall.
/// Best effort: a refused removal still leaves the periodic flush to
/// clear it within one re-mark period.
fn remove_ignore_mark(group: std::os::unix::io::RawFd, file: &std::fs::File) -> bool {
    // SAFETY: libc call; the group and the held event fd are valid,
    // and a NULL pathname addresses the held fd's inode.
    let rc = unsafe {
        libc::fanotify_mark(
            group,
            libc::FAN_MARK_REMOVE | libc::FAN_MARK_IGNORED_MASK,
            libc::FAN_OPEN,
            file.as_raw_fd(),
            std::ptr::null(),
        )
    };
    rc == 0
}

/// What placing one ignore mark did: `Marked` means a mark is newly in
/// place for an unchanged file, `Refused` that the kernel took none
/// (mark limit, permission, or the cap — the user-space cache still
/// decides), and `Changed` that the file moved under the proof so its
/// mark was removed again and nothing may be cached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IgnoreMarkOutcome {
    Marked,
    Refused,
    Changed,
}

/// Removes every filesystem mark of the group (inode ignore marks
/// stay): flushing filesystem marks needs `CAP_SYS_ADMIN`, so it runs
/// only where the startup grant is still held — the arming-timeout
/// cleanup below. Best effort.
fn flush_filesystem_marks(group: std::os::unix::io::RawFd) -> bool {
    // SAFETY: libc call on the live group; flush takes no path.
    let rc = unsafe {
        libc::fanotify_mark(
            group,
            libc::FAN_MARK_FLUSH | libc::FAN_MARK_FILESYSTEM,
            0,
            libc::AT_FDCWD,
            std::ptr::null(),
        )
    };
    rc == 0
}

/// Clears the period ignore-mark state after the periodic flush —
/// but only when the flush succeeded. A failed flush leaves the marks
/// installed, so the counter and the per-period set stay: the cap
/// keeps bounding new marks instead of undercounting past it.
fn reset_marks_after_flush(ctx: &mut DrainCtx<'_>, flushed: bool) {
    if flushed {
        ctx.ignore_marks = 0;
        ctx.marked_this_period.clear();
    }
}

/// Removes every inode ignore mark of the group (the filesystem marks
/// stay): `FAN_MARK_FLUSH` of inode marks needs no capability, so it
/// works after the post-setup shed. Best effort.
fn flush_ignore_marks(group: std::os::unix::io::RawFd) -> bool {
    // SAFETY: libc call on the live group; flush takes no path.
    let rc = unsafe {
        libc::fanotify_mark(
            group,
            libc::FAN_MARK_FLUSH,
            0,
            libc::AT_FDCWD,
            std::ptr::null(),
        )
    };
    rc == 0
}

impl DrainCtx<'_> {
    /// Records a certain negative: cached in user space, and filtered
    /// in the kernel while the ignore-mark budget lasts. A file that
    /// moved under its proof is neither cached nor left marked: its
    /// next open re-proves the new content.
    fn note_negative(&mut self, generation: FileGeneration, file: &std::fs::File) {
        match self.mark_ignored_for(generation, file) {
            IgnoreMarkOutcome::Marked | IgnoreMarkOutcome::Refused => {
                self.cache.note_decided(generation, false);
            }
            IgnoreMarkOutcome::Changed => {}
        }
    }

    /// Places the kernel ignore mark for one proved-negative
    /// generation, at most once per flush period. After marking, the
    /// file's size and ctime are re-checked: a writer between the
    /// proof reads and the mark would otherwise leave the new content
    /// suppressed, so a changed file has its mark removed again and
    /// reports `Changed` (the caller must not cache it).
    fn mark_ignored_for(
        &mut self,
        generation: FileGeneration,
        file: &std::fs::File,
    ) -> IgnoreMarkOutcome {
        if self.ignore_marks >= LEARN_IGNORE_MARK_CAP {
            return IgnoreMarkOutcome::Refused;
        }
        if !self.marked_this_period.insert(generation) {
            return IgnoreMarkOutcome::Refused;
        }
        if !ignore_negative_inode(self.group, file) {
            self.marked_this_period.remove(&generation);
            return IgnoreMarkOutcome::Refused;
        }
        let unchanged = match file_generation(file) {
            Ok(fresh) => {
                fresh.2 == generation.2 && fresh.3 == generation.3 && fresh.4 == generation.4
            }
            Err(_) => false,
        };
        if !unchanged {
            remove_ignore_mark(self.group, file);
            self.marked_this_period.remove(&generation);
            return IgnoreMarkOutcome::Changed;
        }
        self.ignore_marks += 1;
        IgnoreMarkOutcome::Marked
    }

    /// Decides every event in one read buffer. Returns whether the
    /// drain continues, and how many records were parsed: the tail
    /// owes `snapshot / unit` events and subtracts one per parsed
    /// record, so the count — not the bytes — drives it. A send
    /// failure (`false`) leaves the unread rest closed with the loss
    /// already marked; an unparseable record closes the tail's fds,
    /// marks the lost tail, and still continues (`true`).
    fn process_read(&mut self, buf: &[u8], window: SendWindow) -> (bool, usize) {
        let len = buf.len();
        let mut offset = 0usize;
        let mut parsed = 0usize;
        while offset < len {
            let event = match parse_fanotify_event(&buf[offset..len]) {
                Ok(event) => event,
                Err(_) => {
                    // Unparseable tail: best-effort close of the fds
                    // its length fields still describe, then stop.
                    close_unread_tail(buf, offset, len);
                    self.state.lost_tail.store(true, Ordering::Release);
                    self.state.loss_other.fetch_add(1, Ordering::Relaxed);
                    return (true, parsed);
                }
            };
            offset += event.total_len;
            parsed += 1;
            if !self.process_event(event, window) {
                close_unread_tail(buf, offset, len);
                return (false, parsed);
            }
        }
        (true, parsed)
    }

    fn send(&self, msg: LearnMsg, window: SendWindow) -> bool {
        send_learn_in(self.tx, self.state, msg, window)
    }

    /// Files one group read error with the shared live/tail meaning:
    /// the failed read's head event is unproven, so it is counted in
    /// telemetry (`unreadable` plus the read-error loss counter) and in
    /// the report (`lost_tail`), then the drain continues — a lone
    /// error never abandons the queue. The 1 ms pacing keeps a
    /// persistently failing fd from hot-spinning the drain.
    fn note_read_error(&mut self) {
        self.stats.unreadable = self.stats.unreadable.saturating_add(1);
        self.state.loss_read_error.fetch_add(1, Ordering::Relaxed);
        self.state.lost_tail.store(true, Ordering::Release);
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    /// Counts one device-node miss (`EBUSY`/`ENXIO`/`ENODEV`) as
    /// unreadable without filing it: the head event named a file the
    /// observer could never open (a single-open device held by its
    /// owner, a vanished node), not a lost learning event. No pacing:
    /// each miss consumes a head, so it cannot spin, and a 1 ms sleep
    /// per miss would turn a burst of device events into a tail-deadline
    /// loss.
    fn note_unreadable_without_filing(&mut self) {
        self.stats.unreadable = self.stats.unreadable.saturating_add(1);
    }

    fn process_event(&mut self, event: ParsedFanotifyEvent, window: SendWindow) -> bool {
        self.stats.events = self.stats.events.saturating_add(1);
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
            // Marks survive a queue overflow, so no re-mark here: the
            // periodic pass covers new mounts, and re-opening every
            // mount per overflow record would slow the drain exactly
            // when it is already behind.
            self.stats.overflows = self.stats.overflows.saturating_add(1);
            return self.send(LearnMsg::QueueOverflow, window);
        }
        if event.fd < 0 {
            return true;
        }
        set_cloexec(event.fd);
        // SAFETY: the kernel sent an owned event fd.
        let file = unsafe { std::fs::File::from_raw_fd(event.fd) };
        if event.pid as u32 == self.self_pid {
            return true;
        }
        let generation = match file_generation(&file) {
            Ok(generation) => generation,
            Err(_) => return true,
        };
        if !self.cache.needs_check(generation) {
            if self.cache.decided_provider(generation) != Some(true) {
                // A known negative that still reports opens (its mark was
                // flushed, refused or evicted): mark it again, at most
                // once per flush period.
                let _ = self.mark_ignored_for(generation, &file);
                return true;
            }
            // A later open of a sent file: tally the load. The pid
            // falls back to the metadata capture when the loader is
            // already gone (lower-bound-correct for counts).
            let Some(pid) = tally_pid(&event, pidfd.as_ref()) else {
                return true;
            };
            let (dev, ino) = (generation.0, generation.1);
            if !self.send(LearnMsg::Load { dev, ino, pid }, window) {
                return false;
            }
            self.stats.sent_loads = self.stats.sent_loads.saturating_add(1);
            return true;
        }
        self.stats.checked = self.stats.checked.saturating_add(1);
        // The loader is named inside the proof, after the cheap byte
        // tests admitted the file and before the full parse, bracketed
        // by pidfd liveness.
        let proved = prove_with_loader(&file, || match pidfd.as_ref() {
            Some(pidfd) => loader_exe_for_pidfd(pidfd),
            None => (None, Some(LOADER_EXE_UNREADABLE_REASON)),
        });
        let (loader_exe, loader_unknown_reason) = match proved {
            Ok(Some(loader)) => loader,
            Ok(None) => {
                self.note_negative(generation, &file);
                return true;
            }
            Err(_) => {
                // Unreadable now: not cached, retried on the next open.
                self.stats.unreadable = self.stats.unreadable.saturating_add(1);
                return true;
            }
        };
        self.stats.proved = self.stats.proved.saturating_add(1);
        // Provider-positive: tally this first run and send Load ahead
        // of the candidate so the staged note counts it.
        let tally = tally_pid(&event, pidfd.as_ref());
        let Some(display_path) = display_path_for(&file) else {
            // Not cached: a later open retries instead of losing
            // this proved provider for the whole capture.
            self.stats.unreadable = self.stats.unreadable.saturating_add(1);
            return true;
        };
        let (dev, ino) = (generation.0, generation.1);
        if let Some(pid) = tally {
            if !self.send(LearnMsg::Load { dev, ino, pid }, window) {
                return false;
            }
            self.stats.sent_loads = self.stats.sent_loads.saturating_add(1);
        }
        let candidate = LearnedCandidate {
            file,
            dev,
            ino,
            display_path,
            loader_exe,
            loader_unknown_reason,
        };
        if !self.send(LearnMsg::Candidate(candidate), window) {
            return false;
        }
        // Only a sent candidate settles the generation: caching a
        // positive before the send would lose the file silently
        // if the send (or the display read above) failed.
        self.cache.note_decided(generation, true);
        self.stats.sent_candidates = self.stats.sent_candidates.saturating_add(1);
        true
    }
}

/// What the kernel reports for the events queued on the group right
/// now: `FIONREAD` sums the queued records — but the unit differs by
/// kernel. Before upstream `68615158c12d` ("fanotify: report full event
/// length for FIONREAD", mainline v7.3, backported to 6.6.157+,
/// 6.12.110+, 6.18.52+ and 7.2.6+) it counts only the 24-byte event
/// header per event; after it the full event, 32 bytes with the pidfd
/// info record. Callers divide by the measured unit
/// (`measure_fionread_unit`) to count events. `None` when the kernel
/// cannot say.
fn queued_event_bytes(raw: std::os::unix::io::RawFd) -> Option<usize> {
    let mut queued: libc::c_int = 0;
    // SAFETY: FIONREAD on a valid fd writes one int.
    let rc = unsafe { libc::ioctl(raw, libc::FIONREAD, &mut queued as *mut libc::c_int) };
    if rc != 0 {
        return None;
    }
    usize::try_from(queued).ok()
}

/// Measures this kernel's `FIONREAD` unit for the learning group: how
/// many bytes one queued event reports. Before upstream `68615158c12d`
/// ("fanotify: report full event length for FIONREAD", mainline v7.3,
/// backported to 6.6.157+, 6.12.110+, 6.18.52+ and 7.2.6+) the kernel
/// counts only the 24-byte event header; after it the full event, 32
/// bytes with the pidfd info record. Runs in `start()` before the
/// filesystem marks, while a private probe inode is the only marked
/// object: one open queues exactly one event, so the snapshot is the
/// unit. Never fails `start()`: any measurement doubt falls back to
/// the 24-byte header, the smaller unit, which only ever over-counts
/// the owed events — and over-draining ends at `EAGAIN` instead of
/// abandoning a tail. Returns the unit and whether it was exactly
/// measured (`true`) or fell back (`false`): with an exact unit the
/// snapshot divides evenly, so leftover owed with an empty queue is a
/// lease-blocked head, not over-count.
fn measure_fionread_unit(group: &OwnedFd) -> (usize, bool) {
    // A probe file nobody else opens: created unmarked (so no event),
    // unlinked at once (no pathname left to swap for a FIFO or to go
    // stale on SIGKILL), inode-marked, opened once through
    // `/proc/self/fd` (exactly one event), drained, unmarked.
    // `tempfile` is a dev-dependency, so plain stdio it is.
    static PROBE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let mut probe = None;
    for _ in 0..8 {
        let id = PROBE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut path = std::env::temp_dir();
        path.push(format!("p11scope-learn-probe-{}-{id}", std::process::id()));
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => {
                probe = Some((file, path));
                break;
            }
            Err(_) => continue,
        }
    }
    let Some((probe, path)) = probe else {
        return (FANOTIFY_META_LEN, false);
    };
    // Unlink while open: the inode stays alive behind the fd for the
    // mark and the fd reopen below, but no pathname remains. Unlinked
    // once, with no guard: a second unlink could delete a file someone
    // else created at that name since.
    let _ = std::fs::remove_file(&path);
    // SAFETY: libc call; the group and probe descriptors are valid, and
    // a NULL pathname marks the probe's inode (the default mark type).
    let marked = 0
        == unsafe {
            libc::fanotify_mark(
                group.as_raw_fd(),
                libc::FAN_MARK_ADD,
                libc::FAN_OPEN,
                probe.as_raw_fd(),
                std::ptr::null(),
            )
        };
    if !marked {
        return (FANOTIFY_META_LEN, false);
    }
    // Reopen through the fd, never the pathname: a pathname reopen in a
    // caller-owned TMPDIR could be swapped for a FIFO (blocking `start`)
    // or hang on a hung mount. `O_NONBLOCK` is defense in depth (a
    // regular file ignores it).
    let proc_fd = format!("/proc/self/fd/{}", probe.as_raw_fd());
    let _opened = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&proc_fd)
        .ok();
    let snapshot = queued_event_bytes(group.as_raw_fd());
    let mut buf = [0u8; 4096];
    // SAFETY: libc read into a live buffer; NONBLOCK so no stall.
    let got = unsafe {
        libc::read(
            group.as_raw_fd(),
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len(),
        )
    };
    if got > 0 {
        close_unread_tail(&buf, 0, got as usize);
    }
    // SAFETY: as above; removes the probe mark again. Best effort: the
    // probe file is deleted either way, so a stuck mark watches nothing.
    unsafe {
        libc::fanotify_mark(
            group.as_raw_fd(),
            libc::FAN_MARK_REMOVE,
            libc::FAN_OPEN,
            probe.as_raw_fd(),
            std::ptr::null(),
        );
    }
    fionread_unit_from_probe(snapshot, got, &buf)
}

/// Decides the `FIONREAD` unit from one probe round: the snapshot is
/// accepted only when the drain read back exactly one record and the
/// snapshot is exactly the 24-byte header or exactly the read size
/// (24-in-32 on an old kernel, 32-in-32 on a new one). Anything else —
/// no snapshot, no record, several records, a near-miss or oversized
/// snapshot — falls back to the 24-byte header (over-counts, safe).
/// Returns the unit and whether it was exactly measured (`true`) or
/// fell back (`false`).
fn fionread_unit_from_probe(
    snapshot: Option<usize>,
    got: libc::ssize_t,
    buf: &[u8],
) -> (usize, bool) {
    let Ok(got) = usize::try_from(got) else {
        return (FANOTIFY_META_LEN, false);
    };
    let Some(snapshot) = snapshot else {
        return (FANOTIFY_META_LEN, false);
    };
    if snapshot != FANOTIFY_META_LEN && snapshot != got {
        return (FANOTIFY_META_LEN, false);
    }
    if buf.len() < got {
        return (FANOTIFY_META_LEN, false);
    }
    if count_parsed_records(&buf[..got]) != 1 {
        return (FANOTIFY_META_LEN, false);
    }
    (snapshot, true)
}

/// One meaning for group reads in the live loop and the tail: data to
/// decide, an empty queue (`EAGAIN`, or a zero read, which a fanotify
/// group never returns), an interrupted call to retry at once, a
/// device-node read that found no openable file (`EBUSY`/`ENXIO`/`ENODEV`
/// from a single-open or vanished device — counted as unreadable, never
/// filed), or a failed read whose head event is unproven — counted and
/// filed (see `note_read_error`), then the drain continues with the rest
/// of the queue instead of abandoning it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupReadOutcome {
    Data(usize),
    Empty,
    Interrupted,
    Unreadable,
    Failed,
}

fn classify_group_read(got: libc::ssize_t) -> GroupReadOutcome {
    if got > 0 {
        return GroupReadOutcome::Data(got as usize);
    }
    if got == 0 {
        return GroupReadOutcome::Empty;
    }
    // Raw errnos, not `ErrorKind`: several distinct fanotify failures
    // share one kind (`EBUSY` and `EACCES` are both `Other`/`PermissionDenied`
    // on some mappings), but only device-node misses are unreadable without
    // filing. `EWOULDBLOCK` equals `EAGAIN` on Linux, so one arm covers the
    // empty queue; a conflicting lease can also surface here (see the tail's
    // `Empty`-with-owed re-check).
    match std::io::Error::last_os_error().raw_os_error() {
        Some(errno) if errno == libc::EINTR => GroupReadOutcome::Interrupted,
        Some(errno) if errno == libc::EAGAIN => GroupReadOutcome::Empty,
        Some(errno) if errno == libc::EBUSY || errno == libc::ENXIO || errno == libc::ENODEV => {
            GroupReadOutcome::Unreadable
        }
        _ => GroupReadOutcome::Failed,
    }
}

/// User-space bound on the unlimited kernel queue: queued events past
/// `cap_bytes` of records (about 262,000 events at 32 `FIONREAD` bytes
/// per event, about 349,000 at 24 — the unit differs by kernel, see
/// `measure_fionread_unit` — a few tens of MiB of kernel memory either
/// way) are shed. 16 times the default finite queue, so only a drain
/// that truly cannot keep up reaches it.
const LEARN_BACKLOG_CAP_BYTES: usize = 8 << 20;

/// Sheds a backlog past `cap_bytes` (production passes
/// `LEARN_BACKLOG_CAP_BYTES`): reads and closes queued events undecided
/// down to half of `cap_bytes` and files the named overflow once for
/// the episode — the finite-queue overflow, at a bound the drain
/// chooses. Counts events, not bytes: the shed owes `snapshot / unit`
/// events minus one per parsed record, so a 24-byte-unit kernel sheds
/// the same backlog as a 32-byte one. Returns false when the overflow
/// could not be sent (the drain must exit).
fn shed_backlog_past_cap(
    raw: std::os::unix::io::RawFd,
    ctx: &mut DrainCtx<'_>,
    buf: &mut [u8],
    cap_bytes: usize,
) -> bool {
    let Some(queued) = queued_event_bytes(raw) else {
        return true;
    };
    if queued <= cap_bytes {
        return true;
    }
    let unit = ctx.fionread_unit.max(1);
    let mut owed = queued.div_ceil(unit).saturating_sub(cap_bytes / unit / 2);
    let mut consecutive_errors = 0usize;
    while owed > 0 {
        // SAFETY: libc read into a live buffer; NONBLOCK so no stall.
        let read = unsafe { libc::read(raw, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if read < 0 {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(errno) if errno == libc::EINTR => continue,
                Some(errno) if errno == libc::EAGAIN => break,
                _ => {
                    // A failed head was consumed: account it and continue
                    // past it instead of pinning the rest behind it,
                    // bounded so a persistently failing fd ends the shed.
                    owed = owed.saturating_sub(1);
                    consecutive_errors = consecutive_errors.saturating_add(1);
                    if consecutive_errors > 1024 {
                        break;
                    }
                    continue;
                }
            }
        }
        consecutive_errors = 0;
        if read == 0 {
            break;
        }
        let read = read as usize;
        close_unread_tail(buf, 0, read);
        let shed = count_parsed_records(&buf[..read]);
        if shed == 0 {
            // Unaccountable bytes (no parseable record): stop instead
            // of spinning without progress — the backlog is still past
            // the cap, so the next check re-sheds.
            break;
        }
        owed = owed.saturating_sub(shed);
    }
    ctx.stats.overflows = ctx.stats.overflows.saturating_add(1);
    ctx.state.loss_shed.fetch_add(1, Ordering::Relaxed);
    ctx.send(LearnMsg::QueueOverflow, SendWindow::Live)
}

/// The end-of-capture tail: every event queued when the stop landed
/// happened inside the capture, so it is drained and decided like any
/// other — a busy host never has an empty queue at the stop, and
/// counting that queue as lost would file a learned-loss gap on every
/// busy desktop. Events queued after the snapshot are opens after the
/// capture ended (post-scope, like the engine's own end flush).
/// Returns true when the tail was fully decided; false (and the lost
/// tail marked) when it could not be within the bound.
fn drain_final_tail(raw: std::os::unix::io::RawFd, ctx: &mut DrainCtx<'_>, buf: &mut [u8]) -> bool {
    drain_final_tail_with(raw, ctx, buf, |fd, buf| {
        // SAFETY: libc read into a live buffer; NONBLOCK so no stall.
        unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) }
    })
}

/// The tail drain with an injectable read: production passes the
/// blocking-safe `read(2)` above, tests simulate read errors without
/// a group. A read error is counted and filed (`note_read_error`)
/// and the tail continues with the rest of the snapshot instead of
/// abandoning the whole tail as lost.
fn drain_final_tail_with(
    raw: std::os::unix::io::RawFd,
    ctx: &mut DrainCtx<'_>,
    buf: &mut [u8],
    mut read: impl FnMut(std::os::unix::io::RawFd, &mut [u8]) -> libc::ssize_t,
) -> bool {
    let deadline = tail_deadline_from(ctx.state);
    let window = SendWindow::Final(deadline);
    let Some(snapshot) = queued_event_bytes(raw) else {
        ctx.state.loss_other.fetch_add(1, Ordering::Relaxed);
        return false;
    };
    // Events, not bytes: on a 24-byte-unit kernel a byte count stops
    // after 75% of the snapshot (each record reads back 32 bytes),
    // silently dropping the rest — so the tail owes `snapshot / unit`
    // events minus one per parsed record. The ceiling over-counts by
    // less than one event, which ends at `EAGAIN` instead of
    // abandoning a tail.
    let mut owed = snapshot.div_ceil(ctx.fionread_unit.max(1));
    while owed > 0 {
        if std::time::Instant::now() >= deadline {
            ctx.state.loss_tail_deadline.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        let got = read(raw, buf);
        match classify_group_read(got) {
            GroupReadOutcome::Data(got) => {
                let (cont, decided) = ctx.process_read(&buf[..got], window);
                owed = owed.saturating_sub(decided);
                if !cont {
                    return false;
                }
            }
            GroupReadOutcome::Empty => {
                // Owed events remain but the read says empty: the empty
                // could be a conflicting-lease `EWOULDBLOCK` (the same
                // errno as `EAGAIN`) that consumed the head with more
                // queued behind it. Re-check the queue: more bytes means
                // continue, and an unreadable queue gives up. An empty
                // queue with an exact unit means the tail events were
                // lease-blocked (the snapshot divides evenly, so leftover
                // owed is the consumed-head count): count them, decided.
                // An empty queue after a fallback is the ceiling over-count
                // (harmless, decided).
                match queued_event_bytes(raw) {
                    Some(0) => {
                        if ctx.fionread_exact {
                            ctx.stats.unreadable = ctx.stats.unreadable.saturating_add(owed as u64);
                        }
                        return true;
                    }
                    Some(_) => continue,
                    None => {
                        ctx.state.loss_other.fetch_add(1, Ordering::Relaxed);
                        return false;
                    }
                }
            }
            GroupReadOutcome::Interrupted => continue,
            GroupReadOutcome::Unreadable => {
                // The head named an unopenable device node and was
                // consumed: account it without filing.
                owed = owed.saturating_sub(1);
                ctx.note_unreadable_without_filing();
                continue;
            }
            GroupReadOutcome::Failed => {
                // The head was consumed unproven: account it, file it,
                // and continue with the rest.
                owed = owed.saturating_sub(1);
                ctx.note_read_error();
                continue;
            }
        }
    }
    true
}

/// Starts one periodic re-mark pass on a helper thread and returns
/// at once — the drain never waits for it, not even bounded: a wait
/// here would eat the stop-tail budget before the drain sees the stop.
/// The helper holds no group fd of its own, only the shared slot,
/// which it locks solely around each `fanotify_mark`, so a helper hung
/// in a mount open pins nothing. `pending` carries the in-flight
/// pass's receiver across ticks. Returns false when no pass could start
/// (spawn failure) or when a pass is still pending from the previous
/// period — both leave coverage unproven, which files the
/// unavailable-learning gap at once. A pending pass starts nothing
/// (never stacks another thread), but the tick is a gap, not a silent
/// skip.
fn spawn_remark_pass(
    shared: &Arc<Mutex<Option<OwnedFd>>>,
    previous: &BTreeSet<MountIdentity>,
    pending: &mut Option<Receiver<(BTreeSet<MountIdentity>, usize)>>,
    mark: impl FnOnce(
        Arc<Mutex<Option<OwnedFd>>>,
        BTreeSet<MountIdentity>,
    ) -> (BTreeSet<MountIdentity>, usize)
    + Send
    + 'static,
) -> bool {
    if pending.is_some() {
        return false;
    }
    let helper_shared = Arc::clone(shared);
    let prev = previous.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let helper = std::thread::Builder::new()
        .name("p11scope-learn-remark".to_string())
        .spawn(move || {
            let _ = tx.send(mark(helper_shared, prev));
        });
    let helper = match helper {
        Ok(helper) => helper,
        Err(_) => return false,
    };
    // Dropping the handle detaches the helper; forgetting it would
    // leave the thread joinable (leaked) instead. Its receiver stays
    // pending so a later tick adopts its result.
    drop(helper);
    *pending = Some(rx);
    true
}

/// Adopts a landed re-mark result without blocking: `Some` when a pass
/// finished (adopt its coverage) or died (keep the previous set with
/// one uncovered — coverage unproven), `None` when a pass is still
/// running or none is in flight. Called every drain tick so a result
/// lands promptly; only spawning waits for the 30 s period.
fn adopt_remark_result(
    previous: &BTreeSet<MountIdentity>,
    pending: &mut Option<Receiver<(BTreeSet<MountIdentity>, usize)>>,
) -> Option<(BTreeSet<MountIdentity>, usize)> {
    let rx = pending.as_ref()?;
    match rx.try_recv() {
        Ok(result) => {
            *pending = None;
            Some(result)
        }
        Err(std::sync::mpsc::TryRecvError::Empty) => None,
        Err(std::sync::mpsc::TryRecvError::Disconnected) => {
            *pending = None;
            Some((previous.clone(), 1))
        }
    }
}

/// Prints the drain's `-v` telemetry line: progress counts plus the
/// per-source loss counters. Counts only, never paths, pids or bytes.
fn print_drain_telemetry(ctx: &DrainCtx<'_>, state: &LearnShutdownState) {
    let stats = &ctx.stats;
    eprintln!(
        "p11scope: file learning: {} events, {} checked, {} providers, {} staged, {} loads, {} overflows, {} unreadable, shed {}, tail_deadline {}, read_error {}, send_deadline {}, join_timeout {}, other {}",
        stats.events,
        stats.checked,
        stats.proved,
        stats.sent_candidates,
        stats.sent_loads,
        stats.overflows,
        stats.unreadable,
        state.loss_shed.load(Ordering::Relaxed),
        state.loss_tail_deadline.load(Ordering::Relaxed),
        state.loss_read_error.load(Ordering::Relaxed),
        state.loss_send_deadline.load(Ordering::Relaxed),
        state.loss_join_timeout.load(Ordering::Relaxed),
        state.loss_other.load(Ordering::Relaxed),
    );
}

/// Prints the final learner `-v` line after the join: the drain's last
/// stored counters plus the current loss totals, so post-drain bumps
/// (panic, join timeout) appear. A poisoned or missing store prints
/// zeros for progress (the loss counters are still live atomics).
fn print_final_telemetry(state: &LearnShutdownState) {
    let stats = state
        .final_stats
        .lock()
        .ok()
        .map(|guard| *guard)
        .unwrap_or_default();
    eprintln!(
        "p11scope: file learning: {} events, {} checked, {} providers, {} staged, {} loads, {} overflows, {} unreadable, shed {}, tail_deadline {}, read_error {}, send_deadline {}, join_timeout {}, other {}",
        stats.events,
        stats.checked,
        stats.proved,
        stats.sent_candidates,
        stats.sent_loads,
        stats.overflows,
        stats.unreadable,
        state.loss_shed.load(Ordering::Relaxed),
        state.loss_tail_deadline.load(Ordering::Relaxed),
        state.loss_read_error.load(Ordering::Relaxed),
        state.loss_send_deadline.load(Ordering::Relaxed),
        state.loss_join_timeout.load(Ordering::Relaxed),
        state.loss_other.load(Ordering::Relaxed),
    );
}

/// Stores the drain's counters for the join's final line: called at
/// every telemetry tick and at drain exit, so a drain that panics still
/// leaves its last tick behind. Poison is harmless (the store is
/// best-effort; the final line falls back to zeros).
fn store_final_stats(state: &LearnShutdownState, stats: &DrainStats) {
    if let Ok(mut guard) = state.final_stats.lock() {
        *guard = *stats;
    }
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
    fionread_unit: usize,
    fionread_exact: bool,
) {
    // Scheduling note: loader processes live ~15 ms, so the drain
    // wants prompt scheduling to name them (files still stage via
    // the unknown-loader reason when it loses the race). The observer
    // sheds CAP_SYS_NICE at startup (caps least privilege), so no
    // setpriority here could help; the drain inherits the observer's
    // nice, and an invoker-niced observer degrades naming latency
    // honestly instead of misnaming.
    let raw = group.as_raw_fd();
    // The group lives in the mutex from now on: `raw` borrows it for
    // the whole loop (poll, read, ignore marks), re-mark helpers lock
    // it only around each `fanotify_mark`, and drain exit takes and
    // drops it — killing the group even while a helper is still stuck
    // in a mount open. The take below is the last fd use.
    let shared_group = Arc::new(Mutex::new(Some(group)));
    let mut ctx = DrainCtx {
        group: raw,
        tx: &tx,
        state: &state,
        self_pid: std::process::id(),
        fionread_unit,
        fionread_exact,
        cache: LearnCache::new(),
        stats: DrainStats::default(),
        ignore_marks: 0,
        marked_this_period: std::collections::HashSet::new(),
    };
    let mut buf = vec![0u8; 64 * 1024];
    let mut last_remark = std::time::Instant::now();
    let mut last_backlog_check = std::time::Instant::now();
    let mut unavailable_sent = false;
    let mut pending_remark: Option<Receiver<(BTreeSet<MountIdentity>, usize)>> = None;
    // The startup pass already left a visible filesystem uncovered:
    // name that partial coverage now, once (data-always), instead of
    // letting traffic on the covered filesystems stand in for it.
    if initial_gap_owed {
        unavailable_sent = true;
        if !send_learn(&tx, &state, LearnMsg::Unavailable) {
            return;
        }
    }
    // Whether the loop ended on an orderly stop (then the queued tail
    // is drained) rather than a failed send or poll.
    let mut stopped = false;
    'drain: loop {
        if state.shutdown.load(Ordering::Acquire) {
            stopped = true;
            break 'drain;
        }
        // A landed re-mark result is adopted on the tick it lands (the
        // spawn never waits for it), so coverage stays fresh without
        // the drain ever blocking on a mount.
        if let Some((next_covered, uncovered)) = adopt_remark_result(&covered, &mut pending_remark)
        {
            covered = next_covered;
            if uncovered > 0 && !unavailable_sent {
                unavailable_sent = true;
                if !send_learn(&tx, &state, LearnMsg::Unavailable) {
                    break 'drain;
                }
            }
        }
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
            // Ignore marks live one re-mark period at most: a change the
            // kernel never reports as a modification (a write through a
            // shared writable mapping) still moves the file's ctime, so
            // after the flush its next open is a new generation and is
            // re-proved. The flush costs one re-queued open per marked
            // file, then the marks come back.
            let flushed = flush_ignore_marks(raw);
            reset_marks_after_flush(&mut ctx, flushed);
            // Coverage is the retained-mark set, never event traffic:
            // a failed re-mark of a retained filesystem is harmless
            // (its startup mark still delivers), but a visible
            // filesystem that no pass ever covered — a new mount the
            // post-shed drain cannot mark — files the finite
            // unavailable-learning gap once, however busy the covered
            // filesystems are. The capture continues (data-always).
            // The pass runs on a detached helper sharing the group: a
            // hung mount must never stall the drain, because the
            // unlimited queue would grow behind it. The spawn never
            // waits — the result lands through the pending receiver on
            // a later tick — and a pass still running from the previous
            // period, or one that cannot start, leaves coverage
            // unproven, which files the unavailable-learning gap. A
            // pending pass starts nothing (never stacks another), but
            // the tick is a gap, not a silent skip.
            // A pass that finished between this iteration's adopt above
            // and the tick would otherwise file a false gap (the spawn
            // sees it still pending): adopt again before spawning, so
            // only a pass still running after ~30 s is unproven.
            if let Some((next_covered, uncovered)) =
                adopt_remark_result(&covered, &mut pending_remark)
            {
                covered = next_covered;
                if uncovered > 0 && !unavailable_sent {
                    unavailable_sent = true;
                    if !send_learn(&tx, &state, LearnMsg::Unavailable) {
                        break 'drain;
                    }
                }
            }
            if !spawn_remark_pass(
                &shared_group,
                &covered,
                &mut pending_remark,
                |shared, prev| mark_visible_filesystems_shared(&shared, &prev),
            ) && !unavailable_sent
            {
                unavailable_sent = true;
                if !send_learn(&tx, &state, LearnMsg::Unavailable) {
                    break 'drain;
                }
            }
            // The join prints the final line from the last store, so
            // store every period even when diagnostics are off now.
            store_final_stats(&state, &ctx.stats);
            if crate::run::capture_diagnostics_on() {
                print_drain_telemetry(&ctx, &state);
            }
        }
        if ready == 0 {
            continue;
        }
        if last_backlog_check.elapsed() >= std::time::Duration::from_secs(1) {
            last_backlog_check = std::time::Instant::now();
            if !shed_backlog_past_cap(raw, &mut ctx, &mut buf, LEARN_BACKLOG_CAP_BYTES) {
                break 'drain;
            }
        }
        // SAFETY: libc read into a live buffer; NONBLOCK so no stall.
        let read = unsafe { libc::read(raw, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        match classify_group_read(read) {
            GroupReadOutcome::Data(got) => {
                if !ctx.process_read(&buf[..got], SendWindow::Live).0 {
                    // The engine is gone or a send hit the tail bound (the
                    // loss is marked): nothing more can be delivered.
                    break 'drain;
                }
            }
            GroupReadOutcome::Empty | GroupReadOutcome::Interrupted => continue,
            GroupReadOutcome::Unreadable => {
                ctx.note_unreadable_without_filing();
                continue;
            }
            GroupReadOutcome::Failed => {
                ctx.note_read_error();
                continue;
            }
        }
    }
    if stopped {
        if !drain_final_tail(raw, &mut ctx, &mut buf) {
            state.lost_tail.store(true, Ordering::Release);
        }
    } else {
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
            state.loss_other.fetch_add(1, Ordering::Relaxed);
        }
    }
    // The group dies here even when a re-mark helper is still stuck in
    // a mount open: taking the shared fd drops the last reference
    // (helpers lock it only around each mark, never across the open),
    // so no filesystem marks and no unread unlimited queue survive the
    // drain. A stuck helper that later finishes finds no group and
    // skips its marks; its result is unadopted. The take never blocks
    // on a mount — a helper mid-mark holds the lock only for the
    // syscall — and poison is benign (no invariant on the value).
    drop(
        shared_group
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take(),
    );
    // The join prints the final line (after reaping, so its panic and
    // timeout bumps appear): store the exit counters for it. A drain
    // that exits past the join bound stores late — the join already
    // printed from the last tick — which is harmless.
    store_final_stats(&state, &ctx.stats);
}

#[cfg(test)]
mod tests {
    use std::os::unix::io::AsRawFd;

    /// One synthetic 32-byte open record with no fds (fd negative, no
    /// pidfd info): the parser accepts it, the drain counts it, and
    /// nothing needs closing. The mask is a plain open bit, never
    /// overflow.
    fn synthetic_open_record() -> [u8; 32] {
        let mut record = [0u8; 32];
        record[0..4].copy_from_slice(&32u32.to_ne_bytes());
        record[4] = super::FANOTIFY_METADATA_VERSION;
        record[8..16].copy_from_slice(&1u64.to_ne_bytes());
        record[16..20].copy_from_slice(&(-1i32).to_ne_bytes());
        record[20..24].copy_from_slice(&1234i32.to_ne_bytes());
        record
    }

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

    /// Device nodes are never marked: `devtmpfs` is a pseudo filesystem
    /// for the mark pass, so the observer never queues opens of `/dev`
    /// entries and never attempts its own open of single-open devices
    /// (ALSA PCMs, TPMs, watchdogs) inside the group read.
    #[test]
    fn learn_mount_marks_skip_devtmpfs() {
        let table = "1 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
             42 1 0:6 / /dev rw,nosuid,relatime - devtmpfs udev rw\n";
        let mut marks: Vec<String> = super::mounts_for_marks(table)
            .iter()
            .map(|mount| mount.point.to_string_lossy().into_owned())
            .collect();
        marks.sort();
        assert_eq!(marks, vec!["/"], "a devtmpfs /dev is skipped, never marked");
    }

    /// An autofs trigger is never marked (opening it would mount and
    /// keep mounted a NAS share every 30 s, and a dead server would hang
    /// the pass): the fstype is skipped like other pseudo filesystems.
    /// A share already mounted still shows through its own real
    /// filesystem entry (nfs/cifs), which is kept.
    #[test]
    fn learn_mount_marks_skip_autofs_but_cover_mounted_share() {
        let table = "100 1 0:100 / /mnt/nas rw,relatime - autofs systemd-1 rw\n\
             101 1 0:101 / /mnt/nas/share rw,relatime - nfs server:/export rw\n\
             1 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n";
        let mut marks: Vec<String> = super::mounts_for_marks(table)
            .iter()
            .map(|mount| mount.point.to_string_lossy().into_owned())
            .collect();
        marks.sort();
        assert_eq!(
            marks,
            vec!["/", "/mnt/nas/share"],
            "the autofs trigger is skipped but the mounted share is kept"
        );
    }

    /// An autofs overmount at an already-mounted real path hides the
    /// lower mount: overmount replacement wins over the pseudo skip, so
    /// the lower locator is removed and never reaches the mark pass
    /// (opening it would open the trigger). A real share already
    /// mounted at a descendant path stays covered through its own entry.
    #[test]
    fn learn_mount_marks_autofs_overmount_hides_lower_real_mount() {
        let table = "1 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
             100 1 8:2 / /mnt/nas rw,relatime - ext4 /dev/sda2 rw\n\
             101 1 0:101 / /mnt/nas rw,relatime - autofs systemd-1 rw\n\
             102 101 0:102 / /mnt/nas/share rw,relatime - nfs server:/export rw\n";
        let mut marks: Vec<String> = super::mounts_for_marks(table)
            .iter()
            .map(|mount| mount.point.to_string_lossy().into_owned())
            .collect();
        marks.sort();
        assert_eq!(
            marks,
            vec!["/", "/mnt/nas/share"],
            "the autofs overmount hides the lower /mnt/nas locator; the mounted share stays"
        );
        // A real descendant mounted *before* the overmount is hidden by
        // it too: opening that path would traverse the trigger, so it
        // is dropped as well.
        let table = "1 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n\
             102 1 0:102 / /mnt/nas/share rw,relatime - nfs server:/export rw\n\
             100 1 8:2 / /mnt/nas rw,relatime - ext4 /dev/sda2 rw\n\
             101 1 0:101 / /mnt/nas rw,relatime - autofs systemd-1 rw\n";
        let mut marks: Vec<String> = super::mounts_for_marks(table)
            .iter()
            .map(|mount| mount.point.to_string_lossy().into_owned())
            .collect();
        marks.sort();
        assert_eq!(
            marks,
            vec!["/"],
            "paths hidden under the trigger are dropped, not marked through it"
        );
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

    fn marked(mount_id: u64, dev_major: u32, dev_minor: u32) -> super::MarkOutcome {
        let identity = mnt(mount_id, dev_major, dev_minor);
        super::MarkOutcome {
            resolved: Some(identity),
            marked: Some(identity),
        }
    }

    fn failed(mount_id: u64, dev_major: u32, dev_minor: u32) -> super::MarkOutcome {
        super::MarkOutcome {
            resolved: Some(mnt(mount_id, dev_major, dev_minor)),
            marked: None,
        }
    }

    fn unresolved() -> super::MarkOutcome {
        super::MarkOutcome {
            resolved: None,
            marked: None,
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
        let (next, uncovered) = super::evaluate_mark_coverage(&covered, &visible, |_| unresolved());
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
        let (next, uncovered) =
            super::evaluate_mark_coverage(&covered, &visible, |_| failed(68, 8, 2));
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
        let (next, uncovered) =
            super::evaluate_mark_coverage(&covered, &visible, |_| failed(68, 8, 1));
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
        let (next, uncovered) = super::evaluate_mark_coverage(&covered, &visible, |_| unresolved());
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
        let (next, uncovered) =
            super::evaluate_mark_coverage(&covered, &visible, |_| failed(68, 8, 2));
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
            if point.as_os_str() == "/mnt/new" {
                marked(68, 8, 2)
            } else {
                unresolved()
            }
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
            super::evaluate_mark_coverage(&covered, &visible, |_| marked(68, 8, 2));
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
        let (next, uncovered) =
            super::evaluate_mark_coverage(&next, &visible, |_| failed(51, 8, 1));
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
        let (next, uncovered) = super::evaluate_mark_coverage(&covered, &visible, |point| {
            if point.as_os_str() == "/" {
                failed(51, 8, 1)
            } else {
                failed(52, 8, 2)
            }
        });
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
            super::evaluate_mark_coverage(&covered, &visible, |_| marked(51, 0, 42));
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
            super::evaluate_mark_coverage(&covered, &visible, |_| marked(68, 8, 2));
        assert_eq!(uncovered, 0, "the overmount's mark covers the path");
        assert_eq!(
            next,
            [mnt(68, 8, 2)].into_iter().collect(),
            "only the actually-marked mount is retained"
        );
        // The overmount is gone; the reappeared snapshot mount cannot
        // be marked (post-shed re-mark without CAP_SYS_ADMIN).
        let (next, uncovered) =
            super::evaluate_mark_coverage(&next, &visible, |_| failed(51, 8, 1));
        assert_eq!(uncovered, 1, "the unmarked reappearance owes the gap");
        assert!(next.is_empty(), "the dead overmount is not retained");
    }

    /// An unchanged shadowed mount stays covered after the capability
    /// shed: both passes resolve `/usr/lib` (snapshot 39) to the
    /// already-marked `/usr` (51), so the post-shed re-mark failure
    /// files no gap. Reproduces the rv2 F1 probe
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
            super::evaluate_mark_coverage(&covered, &visible, |_| marked(51, 0, 42));
        assert_eq!(uncovered, 0, "startup marks cover the shadowed path");
        assert_eq!(
            next,
            [mnt(51, 0, 42)].into_iter().collect(),
            "only the actually-marked mount is retained"
        );
        // Unchanged topology after the shed: the retained mount's
        // re-mark is skipped, the shadowed mount's re-mark fails,
        // but the path still resolves to the marked 51.
        let (next, uncovered) =
            super::evaluate_mark_coverage(&next, &visible, |_| failed(51, 0, 42));
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
                marked(51, 8, 1)
            } else if point.as_os_str() == "/usr/lib" {
                marked(68, 0, 42)
            } else {
                failed(52, 8, 2)
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
    /// `O_CLOEXEC` like the directory handle. The handle reopens the
    /// type-checked probe through its own `/proc/self/fd/N` link, so it
    /// carries no `O_NOFOLLOW` (the kernel refuses that flag on the fd
    /// link with `ELOOP`) and is bound to the probed identity instead;
    /// symlink refusal lives at the `O_PATH` probe. A trailing symlink
    /// still refuses.
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
        // No O_NOFOLLOW on the final handle: it reopens the probed
        // object through its own /proc/self/fd/N link, which leaves no
        // pathname traversal to refuse (and the kernel refuses the flag
        // on that link with ELOOP). The binding is by identity instead:
        // the held fd stats back to the probed file.
        let mut bound: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: fstat on our own live fd.
        assert_eq!(unsafe { libc::fstat(held.as_raw_fd(), &mut bound) }, 0);
        let source = std::fs::metadata(&file).unwrap();
        {
            use std::os::unix::fs::MetadataExt as _;
            assert_eq!(
                (bound.st_dev, bound.st_ino),
                (source.dev(), source.ino()),
                "the file mark fd is the probed object itself"
            );
        }
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

    /// A char-device bind is never opened read-only for marking:
    /// opening `/dev/watchdog` arms it, opening a tty can take a
    /// controlling terminal. Only regular-file binds mark; any other
    /// type is skipped (a fail-closed named gap via the uncovered
    /// count, never silent coverage). The readable-open observer proves
    /// the refusal happens before the open: removing the pre-open type
    /// guard opens `/dev/null` and fails this test. The healthy twin
    /// (a regular file) still opens exactly once, as a regular file.
    #[test]
    fn learn_file_mark_fd_skips_char_devices() {
        let mut device_opens = Vec::new();
        assert!(
            super::open_file_for_mark_with_readable_observer(
                std::path::Path::new("/dev/null"),
                |file_type| device_opens.push(file_type),
            )
            .is_none(),
            "a char-device bind must never open read-only for marking"
        );
        assert!(
            device_opens.is_empty(),
            "a char-device bind must never reach the read-only open: {device_opens:?}"
        );
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("bind-stand-in");
        std::fs::write(&file, "a bound file").unwrap();
        let mut regular_opens = Vec::new();
        assert!(
            super::open_file_for_mark_with_readable_observer(&file, |file_type| {
                regular_opens.push(file_type)
            })
            .is_some(),
            "a regular-file bind still marks"
        );
        assert_eq!(
            regular_opens,
            vec![libc::S_IFREG],
            "a regular-file bind opens exactly once, as a regular file: {regular_opens:?}"
        );
    }

    /// A fifo bind is never opened read-only for marking either: the
    /// pre-open type guard refuses it before the open, so no read-only
    /// handle is ever created. Removing the guard opens the fifo and
    /// fails this test.
    #[test]
    fn learn_file_mark_fd_skips_fifos() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("bind-fifo");
        let path = std::ffi::CString::new(fifo.to_string_lossy().into_owned()).unwrap();
        // SAFETY: mkfifo on an owned path; mode bits only.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o644) }, 0);
        let mut fifo_opens = Vec::new();
        assert!(
            super::open_file_for_mark_with_readable_observer(&fifo, |file_type| {
                fifo_opens.push(file_type)
            })
            .is_none(),
            "a fifo bind must never open read-only for marking"
        );
        assert!(
            fifo_opens.is_empty(),
            "a fifo bind must never reach the read-only open: {fifo_opens:?}"
        );
    }

    /// The type-checked descriptor itself is the open path: an ancestor
    /// replaced between the probe and the reopen — here renamed away
    /// and swapped for a symlink to `/dev`, so the pathname now spells
    /// `/dev/null` — must not redirect the handle. The reopen binds to
    /// the probed regular file (still returned, same identity): a
    /// pathname re-resolution would open the device instead, and its
    /// driver side effects would happen before any final fstat refuses it.
    /// The readable-open observer proves exactly one regular open happened
    /// and no device open did.
    #[test]
    fn learn_file_mark_fd_survives_ancestor_swap_to_device() {
        use std::os::unix::fs::FileTypeExt as _;
        use std::os::unix::fs::MetadataExt as _;
        let dir = tempfile::tempdir().unwrap();
        let ancestor = dir.path().join("real");
        std::fs::create_dir(&ancestor).unwrap();
        // Named so the swapped pathname spells a live device: a
        // pathname re-resolution opens the device here.
        let file = ancestor.join("null");
        std::fs::write(&file, "still the probed file").unwrap();
        let expected = std::fs::metadata(&file).unwrap();
        let moved = dir.path().join("real.moved");
        let mut swap_opens = Vec::new();
        let held = super::open_file_for_mark_with_hooks(
            &file,
            || {
                std::fs::rename(&ancestor, &moved).unwrap();
                std::os::unix::fs::symlink("/dev", &ancestor).unwrap();
            },
            |file_type| swap_opens.push(file_type),
        )
        .expect("the probed file reopens through its own descriptor, not the swapped pathname");
        assert_eq!(
            swap_opens,
            vec![libc::S_IFREG],
            "the swap reopened the probed file once, never the device: {swap_opens:?}"
        );
        assert!(
            std::fs::metadata(&file).is_ok_and(|meta| meta.file_type().is_char_device()),
            "the fixture swapped the pathname onto a live device"
        );
        // SAFETY: fstat on our own held descriptor into a zeroed stat.
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::fstat(held.as_raw_fd(), &mut stat) },
            0,
            "fstat reads the held descriptor"
        );
        assert_eq!(
            (stat.st_dev, stat.st_ino),
            (expected.dev(), expected.ino()),
            "the handle is the probed file, not the swapped-in device"
        );
        assert_eq!(
            stat.st_mode & libc::S_IFMT,
            libc::S_IFREG,
            "the handle stayed a regular file across the swap"
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

    /// A drain stuck in a hung mark open (hard NFS, dead FUSE) must not
    /// hang the capture end: the join is bounded (~1 s), the thread is
    /// detached on timeout, and the loss is reported so the engine
    /// files the overflow gap. The hung open is a fake mark opener
    /// that never returns, run through the real mark evaluator — the
    /// same shape as a drain wedged in its 30 s re-mark. The healthy
    /// twin exits promptly with no loss.
    #[test]
    fn learn_bounded_join_detaches_blocked_drain() {
        let state = std::sync::Arc::new(super::LearnShutdownState::default());
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let visible = vec![visible_mount("/", 51, 8, 1)];
            let _ =
                super::evaluate_mark_coverage(&std::collections::BTreeSet::new(), &visible, |_| {
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    unresolved()
                });
            let _ = done_tx.send(());
        });
        let mut learner = super::FileLearner {
            state,
            thread: Some(super::LearnerThread {
                handle,
                done: done_rx,
            }),
            pending: None,
        };
        let start = std::time::Instant::now();
        let lost = learner.shutdown_and_join();
        let elapsed = start.elapsed();
        assert!(lost, "a timed-out join must report loss (overflow gap)");
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "the join must be bounded (~1 s), not wait for the hung thread: {elapsed:?}"
        );
    }

    /// The healthy twin of the bounded join: a drain that exits on
    /// shutdown joins promptly with no loss and no gap.
    #[test]
    fn learn_bounded_join_healthy_drain_has_no_gap() {
        let state = std::sync::Arc::new(super::LearnShutdownState::default());
        let worker_state = std::sync::Arc::clone(&state);
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            while !worker_state
                .shutdown
                .load(std::sync::atomic::Ordering::Acquire)
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            let _ = done_tx.send(());
        });
        let mut learner = super::FileLearner {
            state,
            thread: Some(super::LearnerThread {
                handle,
                done: done_rx,
            }),
            pending: None,
        };
        let start = std::time::Instant::now();
        let lost = learner.shutdown_and_join();
        let elapsed = start.elapsed();
        assert!(!lost, "a healthy join reports no loss");
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "a healthy join is prompt: {elapsed:?}"
        );
    }

    /// The arming helper is bounded like the end join: blocking work
    /// detaches at the bound with `None` (a hung mount cannot wedge
    /// the start), quick work returns `Some`. The blocking case would
    /// take its full sleep under an unbounded wait, so the elapsed
    /// assertion is what proves the bound.
    #[test]
    fn learn_arming_helper_is_bounded() {
        let bound = std::time::Duration::from_millis(200);
        let start = std::time::Instant::now();
        let blocked: Option<()> = super::run_with_bound("probe-blocked", bound, || {
            std::thread::sleep(std::time::Duration::from_secs(5));
        });
        assert!(blocked.is_none(), "blocking work detaches at the bound");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(3),
            "the arming wait is bounded: {:?}",
            start.elapsed()
        );
        let quick = super::run_with_bound("probe-quick", bound, || 7u32);
        assert_eq!(quick, Some(7), "quick work returns its value");
    }

    // libc 0.2.189 exposes `pthread_getattr_np` but not
    // `pthread_attr_getdetachstate` on Linux, so the detach-state probe
    // declares that one accessor here, test-only.
    unsafe extern "C" {
        fn pthread_attr_getdetachstate(
            attr: *const libc::pthread_attr_t,
            detachstate: *mut libc::c_int,
        ) -> libc::c_int;
    }

    /// Reports the detach state of a live native thread without changing
    /// it: `PTHREAD_CREATE_DETACHED` once its `JoinHandle` was dropped,
    /// `PTHREAD_CREATE_JOINABLE` while it stays joinable. A second
    /// `pthread_detach` is not a portable probe — it segfaults on musl —
    /// so both detach twins read state through this query instead.
    ///
    /// SAFETY: `tid` must identify a live thread that stays alive for the
    /// whole call; both callers hold their worker on a release channel
    /// across the probe.
    unsafe fn detach_state_of(tid: libc::pthread_t) -> libc::c_int {
        unsafe {
            let mut attr: libc::pthread_attr_t = std::mem::zeroed();
            let rc = libc::pthread_getattr_np(tid, &mut attr);
            assert_eq!(rc, 0, "the probe reads the live thread (rc={rc})");
            let mut state: libc::c_int = -1;
            let rc = pthread_attr_getdetachstate(&attr, &mut state);
            assert_eq!(rc, 0, "the probe reads the detach state (rc={rc})");
            let _ = libc::pthread_attr_destroy(&mut attr);
            state
        }
    }

    /// A timed-out arming helper is really detached: its native thread
    /// must not stay joinable (a forgotten `JoinHandle` leaks the
    /// joinable thread resources until process exit). The worker reports
    /// its native handle, stays blocked on a release channel past the
    /// timeout, and the read-only detach-state probe on the live worker
    /// must report detached — never joinable.
    #[test]
    fn learn_arming_timeout_detaches_the_helper() {
        let (id_tx, id_rx) = std::sync::mpsc::channel::<usize>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let bound = std::time::Duration::from_millis(200);
        let timed_out: Option<()> = super::run_with_bound("probe-detach", bound, move || {
            let _ = id_tx.send(unsafe { libc::pthread_self() as usize });
            let _ = release_rx.recv();
        });
        assert!(timed_out.is_none(), "the blocked helper times out");
        let raw_tid = id_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the worker reports its native handle");
        // SAFETY: the live worker's own id, sent as an integer because a
        // raw `pthread_t` is not `Send` on musl, and cast back only while
        // the worker stays blocked until released below.
        let tid: libc::pthread_t = raw_tid as libc::pthread_t;
        let state = unsafe { detach_state_of(tid) };
        let _ = release_tx.send(());
        assert_eq!(
            state,
            libc::PTHREAD_CREATE_DETACHED,
            "a dropped handle leaves the worker detached (state={state})"
        );
    }

    /// Counts this process's open fanotify group fds through
    /// `/proc/self/fd` readlinks: the arming-timeout twin uses it to
    /// prove the owner's duplicate is closed while the stalled helper
    /// still holds the group.
    fn fanotify_fd_count() -> usize {
        let mut count = 0;
        if let Ok(entries) = std::fs::read_dir("/proc/self/fd") {
            for entry in entries.flatten() {
                if let Ok(target) = std::fs::read_link(entry.path())
                    && target.to_string_lossy().contains("anon_inode:[fanotify]")
                {
                    count += 1;
                }
            }
        }
        count
    }

    /// Live arming-timeout proof (privileged): a mark pass stalled past
    /// the worker bound times out, and the timed-out group keeps no
    /// filesystem marks — nothing queues behind the detached helper,
    /// pins mounts or holds the queue — while the owner's duplicate is
    /// closed. The hook marks the scratch filesystem once (proving a
    /// mark existed to remove), then stalls; while it is still stalled
    /// the owner must already have flushed the mark and closed the
    /// duplicate. Run with `sudo -n` (fanotify needs `CAP_SYS_ADMIN`).
    #[test]
    #[ignore = "needs CAP_SYS_ADMIN fanotify group"]
    fn learn_live_arming_timeout_flushes_marks_and_closes_dup() {
        use std::os::unix::io::AsRawFd;
        use std::sync::atomic::{AtomicBool, Ordering};
        let dir = tempfile::tempdir().unwrap();
        let baseline = fanotify_fd_count();
        let group = super::open_learn_group().expect("fanotify group (run as root)");
        let group_fd = group.as_raw_fd();
        let marked = std::sync::Arc::new(AtomicBool::new(false));
        let saw_cancel = std::sync::Arc::new(AtomicBool::new(false));
        let hook_done = std::sync::Arc::new(AtomicBool::new(false));
        let marked_hook = std::sync::Arc::clone(&marked);
        let saw_cancel_hook = std::sync::Arc::clone(&saw_cancel);
        let hook_done_hook = std::sync::Arc::clone(&hook_done);
        let mount = dir.path().to_path_buf();
        let start = std::time::Instant::now();
        let pass = super::arm_with_bound(group, move |group, cancel| {
            let outcome = super::try_mark_filesystem(group, &mount, &[]);
            marked_hook.store(outcome.marked.is_some(), Ordering::Release);
            std::thread::sleep(std::time::Duration::from_secs(5));
            saw_cancel_hook.store(cancel.load(Ordering::Acquire), Ordering::Release);
            hook_done_hook.store(true, Ordering::Release);
            (std::collections::BTreeSet::new(), 0)
        });
        let elapsed = start.elapsed();
        assert!(pass.is_none(), "a stalled arming pass times out");
        assert!(
            elapsed < std::time::Duration::from_secs(3),
            "the arming wait stays bounded: {elapsed:?}"
        );
        assert!(
            marked.load(Ordering::Acquire),
            "the hook placed a mark for the timeout to remove"
        );
        assert!(
            !hook_done.load(Ordering::Acquire),
            "the helper is still stalled past the timeout"
        );
        let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{group_fd}"))
            .expect("fdinfo of the stalled group");
        assert!(
            !fdinfo.lines().any(|line| line.starts_with("fanotify ")
                && (line.contains("sdev:") || line.contains("mnt_id:"))),
            "the timed-out group holds no filesystem marks: {fdinfo}"
        );
        assert_eq!(
            fanotify_fd_count(),
            baseline + 1,
            "only the helper's group stays open while it stalls"
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !hook_done.load(Ordering::Acquire) && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(
            hook_done.load(Ordering::Acquire),
            "the stalled helper exits after its sleep"
        );
        assert!(
            saw_cancel.load(Ordering::Acquire),
            "the helper observed the cancel flag"
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while fanotify_fd_count() != baseline && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert_eq!(
            fanotify_fd_count(),
            baseline,
            "the helper's group closes with it: no leaked group"
        );
    }

    /// The end-join twin: a drain detached at the worker bound is
    /// really detached too, not forgotten-but-joinable, while the
    /// timeout still reports loss for the overflow gap.
    #[test]
    fn learn_bounded_join_detaches_the_drain_thread() {
        let (id_tx, id_rx) = std::sync::mpsc::channel::<usize>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let state = std::sync::Arc::new(super::LearnShutdownState::default());
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let _ = id_tx.send(unsafe { libc::pthread_self() as usize });
            let _ = release_rx.recv();
            let _ = done_tx.send(());
        });
        let mut learner = super::FileLearner {
            state,
            thread: Some(super::LearnerThread {
                handle,
                done: done_rx,
            }),
            pending: None,
        };
        let lost = learner.shutdown_and_join();
        assert!(lost, "a timed-out join must report loss (overflow gap)");
        let raw_tid = id_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the drain reports its native handle");
        // SAFETY: the live drain's own id, sent as an integer because a
        // raw `pthread_t` is not `Send` on musl, and cast back only while
        // the drain stays blocked until released below.
        let tid: libc::pthread_t = raw_tid as libc::pthread_t;
        let state = unsafe { detach_state_of(tid) };
        let _ = release_tx.send(());
        assert_eq!(
            state,
            libc::PTHREAD_CREATE_DETACHED,
            "a dropped handle leaves the drain detached (state={state})"
        );
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

    /// The tail deadline anchors to the recorded stop, not to when the
    /// drain notices it: with the stop a second in the past and bytes
    /// still queued, the tail gives up at once instead of draining
    /// under a fresh bound that would overrun the join. (Unprivileged:
    /// a pipe stands in for the group for the queued-bytes snapshot.)
    #[test]
    fn learn_tail_deadline_anchors_to_the_stop_instant() {
        use std::os::unix::io::FromRawFd;
        let mut fds = [0; 2];
        // SAFETY: libc pipe into a live array; checked before use.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: fresh owned fds from the pipe above.
        let reader = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) };
        let writer = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[1]) };
        let payload = [7u8; 128];
        // SAFETY: libc write of a live buffer to the pipe.
        let written = unsafe {
            libc::write(
                writer.as_raw_fd(),
                payload.as_ptr() as *const libc::c_void,
                payload.len(),
            )
        };
        assert_eq!(written, payload.len() as libc::ssize_t);
        let (tx, _rx) = std::sync::mpsc::sync_channel::<super::LearnMsg>(16);
        let state = std::sync::Arc::new(super::LearnShutdownState::default());
        *state.stop.lock().unwrap() =
            Some(std::time::Instant::now() - std::time::Duration::from_secs(1));
        let mut ctx = super::DrainCtx {
            group: reader.as_raw_fd(),
            tx: &tx,
            state: &state,
            self_pid: std::process::id(),
            fionread_unit: super::FANOTIFY_META_LEN,
            fionread_exact: true,
            cache: super::LearnCache::new(),
            stats: super::DrainStats::default(),
            ignore_marks: 0,
            marked_this_period: std::collections::HashSet::new(),
        };
        let mut buf = vec![0u8; 64 * 1024];
        assert!(
            !super::drain_final_tail(reader.as_raw_fd(), &mut ctx, &mut buf),
            "a tail past the stop-anchored deadline gives up without deciding"
        );
        assert_eq!(ctx.stats.events, 0, "nothing is decided past the deadline");
    }

    /// A tail read error is counted and filed, like a live-loop one:
    /// the failed read's head event is unproven, so it counts as
    /// unreadable plus the shared read-error loss counter and files
    /// the lost tail — and the tail still continues with the rest of
    /// the snapshot instead of abandoning it. (Unprivileged: the read
    /// is injected; the pipe only provides the snapshot.)
    #[test]
    fn learn_tail_read_error_is_counted_and_filed() {
        use std::os::unix::io::FromRawFd;
        use std::sync::atomic::Ordering;
        let mut fds = [0; 2];
        // SAFETY: libc pipe into a live array; checked before use.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: fresh owned fds from the pipe above.
        let reader = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) };
        let writer = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[1]) };
        // One event owed: the failed head is consumed and accounted, so
        // the tail finishes without needing another read.
        let payload = [7u8; 24];
        // SAFETY: libc write of a live buffer to the pipe.
        let written = unsafe {
            libc::write(
                writer.as_raw_fd(),
                payload.as_ptr() as *const libc::c_void,
                payload.len(),
            )
        };
        assert_eq!(written, payload.len() as libc::ssize_t);
        let (tx, _rx) = std::sync::mpsc::sync_channel::<super::LearnMsg>(16);
        let state = std::sync::Arc::new(super::LearnShutdownState::default());
        let mut ctx = super::DrainCtx {
            group: reader.as_raw_fd(),
            tx: &tx,
            state: &state,
            self_pid: std::process::id(),
            fionread_unit: super::FANOTIFY_META_LEN,
            fionread_exact: true,
            cache: super::LearnCache::new(),
            stats: super::DrainStats::default(),
            ignore_marks: 0,
            marked_this_period: std::collections::HashSet::new(),
        };
        let mut buf = vec![0u8; 64 * 1024];
        let mut calls = 0;
        let done = super::drain_final_tail_with(reader.as_raw_fd(), &mut ctx, &mut buf, |_, _| {
            calls += 1;
            // SAFETY: test-only errno for the injected error.
            unsafe {
                *libc::__errno_location() = if calls == 1 { libc::EIO } else { libc::EAGAIN };
            }
            -1
        });
        assert!(done, "the tail continues past a read error");
        assert_eq!(ctx.stats.unreadable, 1, "the error is counted once");
        assert_eq!(
            state.loss_read_error.load(Ordering::Acquire),
            1,
            "the error attributes to the read-error counter"
        );
        assert!(
            state.lost_tail.load(Ordering::Acquire),
            "an unproven head event files the lost tail"
        );
    }

    /// Group reads mean one thing in the live loop and the tail —
    /// both loops classify through the same function: data to decide,
    /// an empty queue (`EAGAIN` or zero), an interrupted call to retry,
    /// a device-node miss counted as unreadable without filing
    /// (`EBUSY`/`ENXIO`/`ENODEV`), or a filed error. (Unprivileged: pure
    /// over injected errno.)
    #[test]
    fn learn_group_read_errors_classify_once_for_both_loops() {
        use super::GroupReadOutcome;
        assert_eq!(super::classify_group_read(32), GroupReadOutcome::Data(32));
        assert_eq!(super::classify_group_read(0), GroupReadOutcome::Empty);
        for (errno, want, why) in [
            (
                libc::EINTR,
                GroupReadOutcome::Interrupted,
                "interrupted retries",
            ),
            (
                libc::EAGAIN,
                GroupReadOutcome::Empty,
                "EAGAIN is an empty queue",
            ),
            (
                libc::EBUSY,
                GroupReadOutcome::Unreadable,
                "a busy single-open device is unreadable, not loss",
            ),
            (
                libc::ENXIO,
                GroupReadOutcome::Unreadable,
                "a vanished device address is unreadable, not loss",
            ),
            (
                libc::ENODEV,
                GroupReadOutcome::Unreadable,
                "a vanished device is unreadable, not loss",
            ),
            (
                libc::EACCES,
                GroupReadOutcome::Failed,
                "permission errors are filed",
            ),
            (
                libc::EMFILE,
                GroupReadOutcome::Failed,
                "fd exhaustion is filed",
            ),
            (
                libc::ENFILE,
                GroupReadOutcome::Failed,
                "system fd exhaustion is filed",
            ),
            (libc::EIO, GroupReadOutcome::Failed, "I/O errors are filed"),
            (libc::EBADF, GroupReadOutcome::Failed, "bad fds are filed"),
        ] {
            // SAFETY: test-only errno for the injected failure.
            unsafe {
                *libc::__errno_location() = errno;
            }
            assert_eq!(super::classify_group_read(-1), want, "{why}");
        }
    }

    /// An unparseable record in a read buffer counts as `other` and
    /// files the lost tail, while the parsed prefix still stands: the
    /// drain continues with the rest. (Unprivileged: synthetic bytes,
    /// no group.)
    #[test]
    fn learn_parse_error_is_counted_as_other_and_filed() {
        use std::sync::atomic::Ordering;
        let (tx, _rx) = std::sync::mpsc::sync_channel::<super::LearnMsg>(16);
        let state = std::sync::Arc::new(super::LearnShutdownState::default());
        let mut ctx = super::DrainCtx {
            group: -1,
            tx: &tx,
            state: &state,
            self_pid: std::process::id(),
            fionread_unit: super::FANOTIFY_META_LEN,
            fionread_exact: true,
            cache: super::LearnCache::new(),
            stats: super::DrainStats::default(),
            ignore_marks: 0,
            marked_this_period: std::collections::HashSet::new(),
        };
        let mut buf = Vec::from(synthetic_open_record());
        buf.extend_from_slice(b"garbage!");
        let (cont, parsed) = ctx.process_read(&buf, super::SendWindow::Live);
        assert!(cont, "a parse error never abandons the drain");
        assert_eq!(parsed, 1, "the parsed prefix still stands");
        assert_eq!(
            state.loss_other.load(Ordering::Acquire),
            1,
            "the parse error attributes to other"
        );
        assert!(
            state.lost_tail.load(Ordering::Acquire),
            "an unparseable record files the lost tail"
        );
    }

    /// A tail whose snapshot cannot be read is given up and counted as
    /// `other`: without the snapshot nothing can be accounted.
    /// (Unprivileged: fd -1 fails `FIONREAD`; the read must not run.)
    #[test]
    fn learn_tail_fionread_failure_is_counted_as_other() {
        use std::sync::atomic::Ordering;
        let (tx, _rx) = std::sync::mpsc::sync_channel::<super::LearnMsg>(16);
        let state = std::sync::Arc::new(super::LearnShutdownState::default());
        let mut ctx = super::DrainCtx {
            group: -1,
            tx: &tx,
            state: &state,
            self_pid: std::process::id(),
            fionread_unit: super::FANOTIFY_META_LEN,
            fionread_exact: true,
            cache: super::LearnCache::new(),
            stats: super::DrainStats::default(),
            ignore_marks: 0,
            marked_this_period: std::collections::HashSet::new(),
        };
        let mut buf = vec![0u8; 64 * 1024];
        let done = super::drain_final_tail_with(-1, &mut ctx, &mut buf, |_, _| {
            panic!("no snapshot means no read");
        });
        assert!(!done, "an unreadable snapshot gives up the tail");
        assert_eq!(
            state.loss_other.load(Ordering::Acquire),
            1,
            "the snapshot failure attributes to other"
        );
    }

    /// A drain thread that panicked counts as `other` at the join: the
    /// report files the lost tail and the telemetry names the panic.
    /// (Unprivileged: a learner assembled around a panicking thread,
    /// never started. The child panic prints, as panics do.)
    #[test]
    fn learn_panicked_drain_join_is_counted_as_other() {
        use std::sync::atomic::Ordering;
        let state = std::sync::Arc::new(super::LearnShutdownState::default());
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let handle = std::thread::Builder::new()
            .name("p11scope-learn-panic-twin".to_string())
            .spawn(move || {
                drop(done_tx);
                panic!("twin drain panic");
            })
            .unwrap();
        let mut learner = super::FileLearner {
            state: std::sync::Arc::clone(&state),
            thread: Some(super::LearnerThread {
                handle,
                done: done_rx,
            }),
            pending: None,
        };
        assert!(
            learner.shutdown_and_join_pumping(|| {}),
            "a panicked drain files the lost tail"
        );
        assert_eq!(
            state.loss_other.load(Ordering::Acquire),
            1,
            "the panic attributes to other"
        );
    }

    /// A panicked drain counts once even when both the join and the
    /// engine's disconnect path observe it: the first attributes to
    /// `other`, the second finds it already filed. (Unprivileged: a
    /// panicking join followed by the engine funnel on the same state.)
    #[test]
    fn learn_panicked_drain_counts_once_across_join_and_disconnect() {
        use std::sync::atomic::Ordering;
        let state = std::sync::Arc::new(super::LearnShutdownState::default());
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let handle = std::thread::Builder::new()
            .name("p11scope-learn-panic-once-twin".to_string())
            .spawn(move || {
                drop(done_tx);
                panic!("twin drain panic for the once count");
            })
            .unwrap();
        let mut learner = super::FileLearner {
            state: std::sync::Arc::clone(&state),
            thread: Some(super::LearnerThread {
                handle,
                done: done_rx,
            }),
            pending: None,
        };
        assert!(
            learner.shutdown_and_join_pumping(|| {}),
            "a panicked drain files the lost tail"
        );
        learner.note_other_loss();
        assert_eq!(
            state.loss_other.load(Ordering::Acquire),
            1,
            "the join panic plus the disconnect funnel count once"
        );
    }

    /// The probe decision accepts the snapshot only for exactly one
    /// record it fits inside: 24-in-32 (a pre-`68615158c12d` kernel)
    /// and 32-in-32 (a newer one). Anything else — no snapshot, a
    /// failed or short read, several records, a snapshot larger than
    /// the record — falls back to the 24-byte header, the smaller
    /// unit, which only ever over-counts. (Unprivileged: pure over
    /// synthetic bytes.)
    #[test]
    fn learn_fionread_unit_accepts_only_a_single_record_probe() {
        let one = synthetic_open_record();
        let mut two = Vec::from(one);
        two.extend_from_slice(&one);
        assert_eq!(
            super::fionread_unit_from_probe(Some(24), 32, &one),
            (24, true),
            "a 24-byte snapshot for one 32-byte record is the old unit"
        );
        assert_eq!(
            super::fionread_unit_from_probe(Some(32), 32, &one),
            (32, true),
            "a 32-byte snapshot for one 32-byte record is the new unit"
        );
        for (snapshot, got, buf, why) in [
            (None, 32, one.as_slice(), "no snapshot"),
            (Some(24), -1, one.as_slice(), "a failed read"),
            (Some(24), 0, one.as_slice(), "an empty read"),
            (Some(0), 32, one.as_slice(), "an empty snapshot"),
            (
                Some(25),
                32,
                one.as_slice(),
                "a snapshot inside the record but neither 24 nor the read size",
            ),
            (
                Some(31),
                32,
                one.as_slice(),
                "a near-miss snapshot is not a unit",
            ),
            (
                Some(64),
                32,
                one.as_slice(),
                "a snapshot larger than the record",
            ),
            (
                Some(48),
                64,
                two.as_slice(),
                "two records are not a unit probe",
            ),
            (Some(24), 32, &[0u8; 32][..], "an unparseable record"),
        ] {
            assert_eq!(
                super::fionread_unit_from_probe(snapshot, got, buf),
                (super::FANOTIFY_META_LEN, false),
                "measurement doubt falls back to the header: {why}"
            );
        }
    }

    /// Event counting across the `FIONREAD` unit change (unprivileged):
    /// on pre-`68615158c12d` kernels one queued event reports 24
    /// `FIONREAD` bytes but reads back 32, so a byte-counted tail stops
    /// after 75% of any snapshot. The tail owes `snapshot / unit`
    /// events minus one per parsed record instead: with a 24-byte unit
    /// and a hundred 32-byte records queued, all hundred are decided.
    /// The pipe provides the snapshot; the read is injected.
    #[test]
    fn learn_tail_counts_events_not_bytes_across_fionread_units() {
        use std::os::unix::io::FromRawFd;
        use std::sync::atomic::Ordering;
        const EVENTS: usize = 100;
        const UNIT: usize = 24;
        let mut fds = [0; 2];
        // SAFETY: libc pipe into a live array; checked before use.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: fresh owned fds from the pipe above.
        let reader = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) };
        let writer = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[1]) };
        // The old-kernel snapshot for the events: 24 bytes each.
        let snapshot = vec![7u8; EVENTS * UNIT];
        // SAFETY: libc write of a live buffer to the pipe.
        let written = unsafe {
            libc::write(
                writer.as_raw_fd(),
                snapshot.as_ptr() as *const libc::c_void,
                snapshot.len(),
            )
        };
        assert_eq!(written, snapshot.len() as libc::ssize_t);
        let (tx, _rx) = std::sync::mpsc::sync_channel::<super::LearnMsg>(16);
        let state = std::sync::Arc::new(super::LearnShutdownState::default());
        let mut ctx = super::DrainCtx {
            group: reader.as_raw_fd(),
            tx: &tx,
            state: &state,
            self_pid: std::process::id(),
            fionread_unit: UNIT,
            fionread_exact: true,
            cache: super::LearnCache::new(),
            stats: super::DrainStats::default(),
            ignore_marks: 0,
            marked_this_period: std::collections::HashSet::new(),
        };
        let mut buf = vec![0u8; 64 * 1024];
        // The records the kernel would return: 32 bytes each, served
        // seven at a time so the accounting spans odd chunk splits.
        let mut queued: Vec<u8> = Vec::with_capacity(EVENTS * 32);
        for _ in 0..EVENTS {
            queued.extend_from_slice(&synthetic_open_record());
        }
        let done =
            super::drain_final_tail_with(reader.as_raw_fd(), &mut ctx, &mut buf, |_, into| {
                if queued.is_empty() {
                    // SAFETY: test-only errno for the injected drain end.
                    unsafe {
                        *libc::__errno_location() = libc::EAGAIN;
                    }
                    return -1;
                }
                let take = queued.len().min(7 * 32);
                into[..take].copy_from_slice(&queued[..take]);
                queued.drain(..take);
                take as libc::ssize_t
            });
        assert!(done, "the tail decides the whole snapshot");
        assert_eq!(
            ctx.stats.events, EVENTS as u64,
            "every queued event is decided, not the first 75%"
        );
        assert!(
            !state.lost_tail.load(Ordering::Acquire),
            "a decided snapshot is not a lost tail"
        );
    }

    /// A tail that reads empty with events still owed and an empty queue
    /// counts the lease-blocked last event instead of dropping it silently
    /// when the unit is exact: with an exactly measured unit the snapshot
    /// divides evenly, so leftover owed means a conflicting-lease
    /// `EWOULDBLOCK` consumed the head. After a fallback the same empty
    /// queue is the ceiling over-count (harmless, no count). (Unprivileged:
    /// the pipe provides the snapshot; the injected read drains it, so the
    /// re-check sees empty.)
    #[test]
    fn learn_tail_empty_with_no_bytes_counts_lease_last_event() {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        use std::sync::atomic::Ordering;
        for (exact, want_unreadable, why) in [
            (true, 1u64, "an exact unit counts the lease-blocked head"),
            (false, 0u64, "a fallback over-count stays silent"),
        ] {
            let mut fds = [0; 2];
            // SAFETY: libc pipe into a live array; checked before use.
            assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
            // SAFETY: fresh owned fds from the pipe above.
            let reader = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) };
            let writer = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[1]) };
            // One event owed.
            let payload = [7u8; 24];
            // SAFETY: libc write of a live buffer to the pipe.
            let written = unsafe {
                libc::write(
                    writer.as_raw_fd(),
                    payload.as_ptr() as *const libc::c_void,
                    payload.len(),
                )
            };
            assert_eq!(written, payload.len() as libc::ssize_t);
            let (tx, _rx) = std::sync::mpsc::sync_channel::<super::LearnMsg>(16);
            let state = std::sync::Arc::new(super::LearnShutdownState::default());
            let mut ctx = super::DrainCtx {
                group: reader.as_raw_fd(),
                tx: &tx,
                state: &state,
                self_pid: std::process::id(),
                fionread_unit: super::FANOTIFY_META_LEN,
                fionread_exact: exact,
                cache: super::LearnCache::new(),
                stats: super::DrainStats::default(),
                ignore_marks: 0,
                marked_this_period: std::collections::HashSet::new(),
            };
            let mut buf = vec![0u8; 64 * 1024];
            let done =
                super::drain_final_tail_with(reader.as_raw_fd(), &mut ctx, &mut buf, |fd, into| {
                    // Drain the pipe (the lease consumed the head), then report
                    // empty: the re-check sees no bytes left.
                    // SAFETY: libc read into a live buffer; the pipe has one payload.
                    let _ = unsafe {
                        libc::read(fd, into.as_mut_ptr() as *mut libc::c_void, into.len())
                    };
                    // SAFETY: test-only errno for the injected lease block.
                    unsafe {
                        *libc::__errno_location() = libc::EAGAIN;
                    }
                    -1
                });
            assert!(done, "the tail decides the drained snapshot: {why}");
            assert_eq!(
                ctx.stats.unreadable, want_unreadable,
                "the empty queue with owed counts once when exact: {why}"
            );
            assert!(
                !state.lost_tail.load(Ordering::Acquire),
                "a counted lease is not a lost tail: {why}"
            );
        }
    }

    /// A tail that reads empty twice with two events owed and an empty
    /// queue counts each lease-blocked head instead of one: with an
    /// exactly measured unit the snapshot divides evenly, so leftover
    /// owed is the consumed-head count. (Unprivileged: the pipe provides
    /// the snapshot; each injected read drains one unit, so the first
    /// re-check sees bytes and the second sees empty.)
    #[test]
    fn learn_tail_empty_with_no_bytes_counts_each_lease_blocked_head() {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        use std::sync::atomic::Ordering;
        let mut fds = [0; 2];
        // SAFETY: libc pipe into a live array; checked before use.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: fresh owned fds from the pipe above.
        let reader = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) };
        let writer = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[1]) };
        // Two events owed.
        let payload = [7u8; 48];
        // SAFETY: libc write of a live buffer to the pipe.
        let written = unsafe {
            libc::write(
                writer.as_raw_fd(),
                payload.as_ptr() as *const libc::c_void,
                payload.len(),
            )
        };
        assert_eq!(written, payload.len() as libc::ssize_t);
        let (tx, _rx) = std::sync::mpsc::sync_channel::<super::LearnMsg>(16);
        let state = std::sync::Arc::new(super::LearnShutdownState::default());
        let mut ctx = super::DrainCtx {
            group: reader.as_raw_fd(),
            tx: &tx,
            state: &state,
            self_pid: std::process::id(),
            fionread_unit: super::FANOTIFY_META_LEN,
            fionread_exact: true,
            cache: super::LearnCache::new(),
            stats: super::DrainStats::default(),
            ignore_marks: 0,
            marked_this_period: std::collections::HashSet::new(),
        };
        let mut buf = vec![0u8; 64 * 1024];
        let mut calls = 0;
        let done =
            super::drain_final_tail_with(reader.as_raw_fd(), &mut ctx, &mut buf, |fd, into| {
                calls += 1;
                // Each lease consumes one head: drain one unit, report
                // empty. The first re-check still sees the second event's
                // bytes; the second sees an empty queue with two owed.
                // SAFETY: libc read of one unit into a live buffer.
                let _ = unsafe {
                    libc::read(
                        fd,
                        into.as_mut_ptr() as *mut libc::c_void,
                        super::FANOTIFY_META_LEN,
                    )
                };
                // SAFETY: test-only errno for the injected lease block.
                unsafe {
                    *libc::__errno_location() = libc::EAGAIN;
                }
                -1
            });
        assert!(done, "the tail decides the drained snapshot");
        assert_eq!(calls, 2, "each lease-blocked head takes one empty read");
        assert_eq!(
            ctx.stats.unreadable, 2,
            "two lease-blocked heads count two, not one"
        );
        assert!(
            !state.lost_tail.load(Ordering::Acquire),
            "counted leases are not a lost tail"
        );
    }

    /// A tail that reads empty with events still owed and bytes still queued
    /// continues past the lease block instead of deciding early: the next
    /// read's events are still decided. (Unprivileged: the pipe provides the
    /// snapshot; the injected reads drain it, so the re-check sees bytes.)
    #[test]
    fn learn_tail_empty_with_bytes_continues_past_lease() {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let mut fds = [0; 2];
        // SAFETY: libc pipe into a live array; checked before use.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: fresh owned fds from the pipe above.
        let reader = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) };
        let writer = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[1]) };
        // Two events owed.
        let payload = [7u8; 48];
        // SAFETY: libc write of a live buffer to the pipe.
        let written = unsafe {
            libc::write(
                writer.as_raw_fd(),
                payload.as_ptr() as *const libc::c_void,
                payload.len(),
            )
        };
        assert_eq!(written, payload.len() as libc::ssize_t);
        let (tx, _rx) = std::sync::mpsc::sync_channel::<super::LearnMsg>(16);
        let state = std::sync::Arc::new(super::LearnShutdownState::default());
        let mut ctx = super::DrainCtx {
            group: reader.as_raw_fd(),
            tx: &tx,
            state: &state,
            self_pid: std::process::id(),
            fionread_unit: super::FANOTIFY_META_LEN,
            fionread_exact: true,
            cache: super::LearnCache::new(),
            stats: super::DrainStats::default(),
            ignore_marks: 0,
            marked_this_period: std::collections::HashSet::new(),
        };
        let mut buf = vec![0u8; 64 * 1024];
        let mut calls = 0;
        let record = synthetic_open_record();
        let done =
            super::drain_final_tail_with(reader.as_raw_fd(), &mut ctx, &mut buf, |fd, into| {
                calls += 1;
                if calls == 1 {
                    // The lease consumes one head: drain one unit, report empty.
                    // The re-check still sees the second event's bytes.
                    // SAFETY: libc read into a live buffer; the pipe has two payloads.
                    let mut dummy = [0u8; 24];
                    let _ = unsafe {
                        libc::read(fd, dummy.as_mut_ptr() as *mut libc::c_void, dummy.len())
                    };
                    // SAFETY: test-only errno for the injected lease block.
                    unsafe {
                        *libc::__errno_location() = libc::EAGAIN;
                    }
                    return -1;
                }
                if calls == 2 {
                    // The next event decides: drain the second unit, serve one record.
                    // SAFETY: libc read into a live buffer; one payload remains.
                    let mut dummy = [0u8; 24];
                    let _ = unsafe {
                        libc::read(fd, dummy.as_mut_ptr() as *mut libc::c_void, dummy.len())
                    };
                    into[..record.len()].copy_from_slice(&record);
                    return record.len() as libc::ssize_t;
                }
                // The queue is drained: empty with nothing left.
                // SAFETY: test-only errno for the injected drain end.
                unsafe {
                    *libc::__errno_location() = libc::EAGAIN;
                }
                -1
            });
        assert!(done, "the tail continues past the lease and decides");
        assert_eq!(
            ctx.stats.events, 1,
            "the event after the lease is decided, not skipped"
        );
    }

    /// The period mark state clears only after a successful flush: a
    /// failed flush keeps the counter and the per-period set, so the
    /// cap keeps bounding new marks instead of undercounting past it.
    #[test]
    fn learn_mark_period_resets_only_after_a_successful_flush() {
        let (tx, _rx) = std::sync::mpsc::sync_channel::<super::LearnMsg>(16);
        let state = std::sync::Arc::new(super::LearnShutdownState::default());
        let mut ctx = super::DrainCtx {
            group: -1,
            tx: &tx,
            state: &state,
            self_pid: std::process::id(),
            fionread_unit: super::FANOTIFY_META_LEN,
            fionread_exact: true,
            cache: super::LearnCache::new(),
            stats: super::DrainStats::default(),
            ignore_marks: 5,
            marked_this_period: std::collections::HashSet::from([(1u64, 2u64, 3u64, 4i64, 5i64)]),
        };
        super::reset_marks_after_flush(&mut ctx, false);
        assert_eq!(ctx.ignore_marks, 5, "a failed flush keeps the counter");
        assert_eq!(
            ctx.marked_this_period.len(),
            1,
            "a failed flush keeps the set"
        );
        super::reset_marks_after_flush(&mut ctx, true);
        assert_eq!(ctx.ignore_marks, 0, "a successful flush resets the counter");
        assert!(
            ctx.marked_this_period.is_empty(),
            "a successful flush clears the set"
        );
    }

    /// A re-mark spawn never waits for the pass: with an injected
    /// mark slower than any bound, the spawn returns at once with the
    /// pass in flight and nothing adopted; ticks while it runs adopt
    /// nothing, start nothing, and file the gap (unproven coverage);
    /// when it lands, the next adopt collects it without spawning. A
    /// pass that dies keeps the previous coverage with one uncovered.
    /// (Unprivileged: the mark is injected and the group is a dummy fd
    /// behind the shared slot.)
    #[test]
    fn learn_remark_spawn_never_waits_and_later_tick_adopts() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dummy = std::fs::File::open("/dev/null").unwrap();
        let group = std::os::fd::OwnedFd::from(dummy);
        let shared = std::sync::Arc::new(std::sync::Mutex::new(Some(group)));
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let mut pending = None;
        let prev = std::collections::BTreeSet::new();
        // The first pass sleeps 2 s: the spawn returns at once.
        let first = std::sync::Arc::clone(&calls);
        let at = std::time::Instant::now();
        assert!(
            super::spawn_remark_pass(&shared, &prev, &mut pending, move |_, _| {
                first.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_secs(2));
                (std::collections::BTreeSet::new(), 7)
            }),
            "the spawn starts the pass"
        );
        assert!(
            at.elapsed() < std::time::Duration::from_secs(1),
            "the spawn never waits for the pass"
        );
        assert!(pending.is_some(), "the pass stays in flight");
        // The spawn returns before the helper runs: wait for the pass
        // to start before asserting start counts.
        let started = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while calls.load(Ordering::SeqCst) != 1 && std::time::Instant::now() < started {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1, "the pass started");
        assert_eq!(
            super::adopt_remark_result(&prev, &mut pending),
            None,
            "a running pass adopts nothing"
        );
        // An immediate second spawn starts nothing while it runs, but
        // the tick files the gap instead of silently skipping.
        let second = std::sync::Arc::clone(&calls);
        assert!(
            !super::spawn_remark_pass(&shared, &prev, &mut pending, move |_, _| {
                second.fetch_add(1, Ordering::SeqCst);
                (std::collections::BTreeSet::new(), 0)
            }),
            "a tick while a pass runs files the gap, not silently skipped"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "no second thread starts while one runs"
        );
        // Once the pass lands, the next adopt collects it.
        std::thread::sleep(std::time::Duration::from_secs(3));
        assert_eq!(
            super::adopt_remark_result(&prev, &mut pending),
            Some((std::collections::BTreeSet::new(), 7)),
            "the landed pass result is adopted"
        );
        assert!(pending.is_none(), "no pass in flight afterwards");
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "adopting starts no new thread"
        );
        // A pass that dies keeps the previous coverage with a gap.
        let (tx, rx) = std::sync::mpsc::channel();
        drop(tx);
        pending = Some(rx);
        assert_eq!(
            super::adopt_remark_result(&prev, &mut pending),
            Some((std::collections::BTreeSet::new(), 1)),
            "a dead pass keeps coverage with one uncovered"
        );
        // The next spawn starts fresh again.
        let fourth = std::sync::Arc::clone(&calls);
        assert!(super::spawn_remark_pass(
            &shared,
            &prev,
            &mut pending,
            move |_, _| {
                fourth.fetch_add(1, Ordering::SeqCst);
                (std::collections::BTreeSet::new(), 0)
            },
        ));
        let restarted = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while calls.load(Ordering::SeqCst) != 2 && std::time::Instant::now() < restarted {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// A re-mark pass still pending at the next 30 s period leaves
    /// coverage unproven: the tick files the unavailable-learning gap
    /// instead of silently skipping. (Unprivileged: the pass sleeps past
    /// any bound, the second spawn is the next period tick.)
    #[test]
    fn learn_remark_pending_at_next_period_files_gap() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dummy = std::fs::File::open("/dev/null").unwrap();
        let group = std::os::fd::OwnedFd::from(dummy);
        let shared = std::sync::Arc::new(std::sync::Mutex::new(Some(group)));
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let mut pending = None;
        let prev = std::collections::BTreeSet::new();
        let first = std::sync::Arc::clone(&calls);
        assert!(
            super::spawn_remark_pass(&shared, &prev, &mut pending, move |_, _| {
                first.fetch_add(1, Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_secs(30));
                (std::collections::BTreeSet::new(), 0)
            }),
            "the first pass starts"
        );
        let started = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while calls.load(Ordering::SeqCst) != 1 && std::time::Instant::now() < started {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1, "the pass is running");
        let at = std::time::Instant::now();
        let second = std::sync::Arc::clone(&calls);
        assert!(
            !super::spawn_remark_pass(&shared, &prev, &mut pending, move |_, _| {
                second.fetch_add(1, Ordering::SeqCst);
                (std::collections::BTreeSet::new(), 0)
            }),
            "a pass still pending at the next period files the gap"
        );
        assert!(
            at.elapsed() < std::time::Duration::from_secs(1),
            "the tick never waits for the stuck pass"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "no second thread starts while one runs"
        );
    }

    /// A re-mark pass that finished before the next 30 s period starts
    /// the next pass with no gap: only a still-pending pass is unproven.
    /// (Unprivileged: the pass returns at once, the adopt collects it,
    /// the second spawn is the next period tick.)
    #[test]
    fn learn_remark_finished_pass_starts_next_without_gap() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let dummy = std::fs::File::open("/dev/null").unwrap();
        let group = std::os::fd::OwnedFd::from(dummy);
        let shared = std::sync::Arc::new(std::sync::Mutex::new(Some(group)));
        let calls = std::sync::Arc::new(AtomicUsize::new(0));
        let mut pending = None;
        let prev = std::collections::BTreeSet::new();
        let first = std::sync::Arc::clone(&calls);
        assert!(
            super::spawn_remark_pass(&shared, &prev, &mut pending, move |_, _| {
                first.fetch_add(1, Ordering::SeqCst);
                (std::collections::BTreeSet::new(), 0)
            }),
            "the first pass starts"
        );
        let landed = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Some((_, uncovered)) = super::adopt_remark_result(&prev, &mut pending) {
                assert_eq!(uncovered, 0, "the finished pass covered all");
                break;
            }
            assert!(
                std::time::Instant::now() < landed,
                "the quick pass lands before the next period"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(pending.is_none(), "no pass in flight after the adopt");
        let second = std::sync::Arc::clone(&calls);
        assert!(
            super::spawn_remark_pass(&shared, &prev, &mut pending, move |_, _| {
                second.fetch_add(1, Ordering::SeqCst);
                (std::collections::BTreeSet::new(), 0)
            }),
            "a finished pass starts the next one with no gap"
        );
        let restarted = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while calls.load(Ordering::SeqCst) != 2 && std::time::Instant::now() < restarted {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// A re-mark helper whose group drain exit already took marks
    /// nothing and panics nowhere: the slot is empty, so every mark
    /// step is refused — the pass resolves what it can and credits
    /// nothing. (Unprivileged: the mount table is the test host's.)
    #[test]
    fn learn_remark_with_taken_group_marks_nothing() {
        let shared: std::sync::Arc<std::sync::Mutex<Option<std::os::fd::OwnedFd>>> =
            std::sync::Arc::new(std::sync::Mutex::new(None));
        let (covered, uncovered) =
            super::mark_visible_filesystems_shared(&shared, &std::collections::BTreeSet::new());
        assert!(covered.is_empty(), "no group means no marks: {covered:?}");
        assert!(uncovered > 0, "unmarked mounts count as uncovered");
    }

    /// Drain exit closes the group while a re-mark helper is still stuck
    /// in its mount open: the take drops the last reference at once,
    /// never waiting for the helper. (Unprivileged: a pipe stands in for
    /// the group — the reader in the slot, a stuck helper holding only
    /// the `Arc`, the take closing the reader so the writer gets `EPIPE`.)
    #[test]
    fn learn_taken_slot_closes_group_while_helper_stuck() {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let mut fds = [0; 2];
        // SAFETY: libc pipe into a live array; checked before use.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: fresh owned fds from the pipe above.
        let reader = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) };
        let writer = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[1]) };
        let shared: std::sync::Arc<std::sync::Mutex<Option<std::os::fd::OwnedFd>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Some(reader)));
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (unblock_tx, unblock_rx) = std::sync::mpsc::channel::<()>();
        let helper_shared = std::sync::Arc::clone(&shared);
        let helper = std::thread::Builder::new()
            .name("p11scope-learn-stuck-twin".to_string())
            .spawn(move || {
                let _ = started_tx.send(());
                // A hung mount open: holds the Arc, never the lock.
                let _ = unblock_rx.recv();
                // After the hang clears, the group is gone.
                let guard = helper_shared
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                assert!(guard.is_none(), "the taken slot stays empty");
            })
            .unwrap();
        started_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        let at = std::time::Instant::now();
        drop(
            shared
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take(),
        );
        assert!(
            at.elapsed() < std::time::Duration::from_secs(1),
            "the take never waits for the stuck helper"
        );
        // SAFETY: libc write to our own pipe whose reader just closed.
        let rc =
            unsafe { libc::write(writer.as_raw_fd(), [7u8].as_ptr() as *const libc::c_void, 1) };
        assert_eq!(rc, -1, "a closed reader breaks the writer");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPIPE),
            "the writer gets EPIPE once the slot is taken"
        );
        drop(unblock_tx);
        helper.join().unwrap();
    }

    /// The arming-timeout dup is read down to `EAGAIN`: the events
    /// queued before the flush are consumed and their fds closed, so
    /// their mounts unpin without waiting for the hung helper.
    /// (Unprivileged: a non-blocking pipe stands in for the group; the
    /// records carry no fds. Completing at all proves the `EAGAIN`
    /// end: a drain that ignored it would spin forever.)
    #[test]
    fn learn_arming_dup_drains_to_eagain_closing() {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let mut fds = [0; 2];
        // SAFETY: libc pipe into a live array; checked before use.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        // SAFETY: fresh owned fds from the pipe above.
        let reader = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[0]) };
        let writer = unsafe { std::os::fd::OwnedFd::from_raw_fd(fds[1]) };
        let mut queued = Vec::new();
        for _ in 0..3 {
            queued.extend_from_slice(&synthetic_open_record());
        }
        // SAFETY: libc write of a live buffer to the pipe.
        let written = unsafe {
            libc::write(
                writer.as_raw_fd(),
                queued.as_ptr() as *const libc::c_void,
                queued.len(),
            )
        };
        assert_eq!(written, queued.len() as libc::ssize_t);
        // SAFETY: fcntl on our own pipe end; the group is non-blocking.
        assert_eq!(
            unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        super::drain_group_closing_to_eagain(reader.as_raw_fd());
        assert_eq!(
            super::queued_event_bytes(reader.as_raw_fd()),
            Some(0),
            "the dup is drained down to EAGAIN"
        );
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
        // The holder shell is dash on Debian; on Fedora it is bash, which execs the
        // trailing `sleep` (verified: only `sleep` survives), so the live pid reads
        // as bash or sleep depending on when the drain samples /proc/pid/exe.
        assert!(
            candidate
                .loader_exe
                .as_deref()
                .is_some_and(|exe| exe.ends_with("/sh")
                    || exe.ends_with("/dash")
                    || exe.ends_with("/bash")
                    || exe.ends_with("/sleep")),
            "the still-live holder is named: {:?} / {:?}",
            candidate.loader_exe,
            candidate.loader_unknown_reason
        );
        holder.kill().unwrap();
        let _ = holder.wait();
    }

    /// Live end-of-capture proof (privileged): stopping the learner while
    /// a child keeps opening files system-wide must drain the events
    /// queued at the stop instead of reporting the stop itself as lost
    /// learning. A busy desktop never has an empty queue at the end of
    /// a capture, so a stop that counts any unread event as loss files
    /// a spurious learned-loss gap on every busy host. Repeated so a
    /// lucky empty queue cannot pass it.
    /// Run with `sudo -n` (fanotify needs `CAP_SYS_ADMIN`).
    #[test]
    #[ignore = "needs CAP_SYS_ADMIN fanotify group"]
    fn learn_live_stop_under_open_churn_drains_without_loss() {
        let dir = tempfile::tempdir().unwrap();
        for index in 0..2000 {
            std::fs::write(dir.path().join(format!("f{index}")), b"not elf").unwrap();
        }
        for round in 0..3 {
            let (mut learner, rx) =
                super::FileLearner::start().expect("fanotify group (run as root)");
            learner.begin_drain().expect("spawn drain");
            // A *child* reopens the files without pause: its opens are
            // never the observer's own, and the queue is never empty
            // when the stop lands.
            let mut churn = std::process::Command::new("sh")
                .args([
                    "-c",
                    "while :; do for f in \"$1\"/f*; do : < \"$f\"; done; done",
                    "sh",
                ])
                .arg(dir.path())
                .spawn()
                .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(700));
            let lost = learner.shutdown_and_join();
            churn.kill().unwrap();
            let _ = churn.wait();
            while rx.try_recv().is_ok() {}
            assert!(
                !lost,
                "round {round}: a stop under ordinary open churn must drain the queued events, not report learned loss"
            );
        }
    }

    /// The rewrite twin of the stop proof (privileged): a child that
    /// truncates its files on every open defeats the kernel ignore
    /// filter (a modification clears it), so every open is queued and
    /// the stop must still decide the queued tail instead of counting
    /// it as loss. A provider opened just before the stop is still
    /// reported through the pumped channel.
    /// Run with `sudo -n` (fanotify needs `CAP_SYS_ADMIN`).
    #[test]
    #[ignore = "needs CAP_SYS_ADMIN fanotify group"]
    fn learn_live_stop_under_rewrite_churn_decides_queued_tail() {
        let dir = tempfile::tempdir().unwrap();
        for index in 0..2000 {
            std::fs::write(dir.path().join(format!("f{index}")), b"").unwrap();
        }
        let c = dir.path().join("tail.c");
        let so = dir.path().join("libtail.so");
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
        for round in 0..3 {
            let (mut learner, rx) =
                super::FileLearner::start().expect("fanotify group (run as root)");
            learner.begin_drain().expect("spawn drain");
            let mut churn = std::process::Command::new("sh")
                .args([
                    "-c",
                    "while :; do for f in \"$1\"/f*; do : > \"$f\"; done; done",
                    "sh",
                ])
                .arg(dir.path())
                .spawn()
                .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(500));
            let opener = std::process::Command::new("cat")
                .arg(&so)
                .stdout(std::process::Stdio::null())
                .status()
                .unwrap();
            assert!(opener.success());
            let mut seen = false;
            let lost = learner.shutdown_and_join_pumping(|| {
                while let Ok(msg) = rx.try_recv() {
                    if let super::LearnMsg::Candidate(candidate) = msg {
                        seen |= candidate.display_path.ends_with("libtail.so");
                    }
                }
            });
            churn.kill().unwrap();
            let _ = churn.wait();
            while let Ok(msg) = rx.try_recv() {
                if let super::LearnMsg::Candidate(candidate) = msg {
                    seen |= candidate.display_path.ends_with("libtail.so");
                }
            }
            assert!(!lost, "round {round}: the queued tail is decided, not lost");
            assert!(
                seen,
                "round {round}: the provider opened before the stop is learned"
            );
        }
    }

    /// Reads a group's queued events for `window`, closing every fd,
    /// and reports whether one of them opened `target` (`st_dev`,
    /// `st_ino`) and whether a kernel overflow record appeared.
    fn read_events_for(
        raw: std::os::unix::io::RawFd,
        target: (u64, u64),
        window: std::time::Duration,
    ) -> (bool, bool) {
        use std::os::unix::io::FromRawFd;
        let deadline = std::time::Instant::now() + window;
        let mut buf = vec![0u8; 64 * 1024];
        let (mut seen, mut overflow) = (false, false);
        while std::time::Instant::now() < deadline {
            // SAFETY: libc read into a live buffer; the group is non-blocking.
            let read = unsafe { libc::read(raw, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if read <= 0 {
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
            let mut offset = 0usize;
            while offset < read as usize {
                let event = super::parse_fanotify_event(&buf[offset..read as usize]).unwrap();
                offset += event.total_len;
                overflow |= event.overflow;
                if let Some(pidfd) = event.pidfd.filter(|fd| *fd >= 0) {
                    // SAFETY: the kernel handed this pidfd to us.
                    drop(unsafe { std::os::fd::OwnedFd::from_raw_fd(pidfd) });
                }
                if event.fd >= 0 {
                    // SAFETY: the kernel handed this event fd to us.
                    let file = unsafe { std::fs::File::from_raw_fd(event.fd) };
                    seen |= super::file_identity(&file).ok() == Some(target);
                }
            }
        }
        (seen, overflow)
    }

    /// Live shed proof (privileged): the unlimited queue absorbs a flood
    /// past the default 16384-event limit without a kernel overflow while
    /// nothing drains it, a backlog under the user-space cap is left
    /// alone (healthy twin), a backlog past it is shed down to half the
    /// cap and filed as the named overflow (failure twin), and the drain
    /// still proves a provider opened afterwards.
    /// Run with `sudo -n` (fanotify needs `CAP_SYS_ADMIN`).
    #[test]
    #[ignore = "needs CAP_SYS_ADMIN fanotify group"]
    fn learn_live_backlog_past_cap_is_shed_as_named_overflow() {
        use std::os::unix::io::AsRawFd;
        let dir = tempfile::tempdir().unwrap();
        for index in 0..2000 {
            std::fs::write(dir.path().join(format!("f{index}")), b"not elf").unwrap();
        }
        let c = dir.path().join("shed.c");
        let so = dir.path().join("libshed.so");
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
        let (mut learner, rx) = super::FileLearner::start().expect("fanotify group (run as root)");
        // Never begin the drain: this thread reads the group itself.
        let super::PendingArming {
            group,
            tx,
            fionread_unit,
            fionread_exact,
            ..
        } = learner.pending.take().expect("armed learner");
        let raw = group.as_raw_fd();
        // 26000 opens with nobody reading: past the default 16384-event
        // queue limit whether the kernel counts 24 or 32 bytes per event
        // (metadata plus the pidfd info record). One process per pass,
        // so the kernel cannot merge the repeats.
        assert!(
            std::process::Command::new("sh")
                .args([
                    "-c",
                    "for pass in 1 2 3 4 5 6 7 8 9 10 11 12 13; do cat \"$1\"/f* > /dev/null; done",
                    "sh",
                ])
                .arg(dir.path())
                .status()
                .unwrap()
                .success()
        );
        let queued = super::queued_event_bytes(raw).expect("FIONREAD");
        assert!(
            queued > 16_384 * (super::FANOTIFY_META_LEN + 8),
            "the unlimited queue holds past the default 16384-event limit: {queued} bytes"
        );
        let state = std::sync::Arc::new(super::LearnShutdownState::default());
        let mut ctx = super::DrainCtx {
            group: raw,
            tx: &tx,
            state: &state,
            self_pid: std::process::id(),
            fionread_unit,
            fionread_exact,
            cache: super::LearnCache::new(),
            stats: super::DrainStats::default(),
            ignore_marks: 0,
            marked_this_period: std::collections::HashSet::new(),
        };
        let mut buf = vec![0u8; 64 * 1024];
        // Healthy twin: a backlog under the cap is never shed.
        assert!(super::shed_backlog_past_cap(
            raw,
            &mut ctx,
            &mut buf,
            queued * 4
        ));
        assert_eq!(ctx.stats.overflows, 0);
        assert!(rx.try_recv().is_err(), "no overflow under the cap");
        // Failure twin: past the cap the backlog is shed and named.
        let cap = 64 * 1024;
        assert!(super::shed_backlog_past_cap(raw, &mut ctx, &mut buf, cap));
        assert_eq!(ctx.stats.overflows, 1);
        assert!(
            matches!(rx.try_recv(), Ok(super::LearnMsg::QueueOverflow)),
            "the shed files the named overflow"
        );
        let after = super::queued_event_bytes(raw).expect("FIONREAD");
        assert!(
            after < queued / 2,
            "the backlog was shed: {queued} -> {after} bytes"
        );
        // The drain still serves: a provider opened now is proved.
        assert!(
            std::process::Command::new("cat")
                .arg(&so)
                .stdout(std::process::Stdio::null())
                .status()
                .unwrap()
                .success()
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        let mut learned = false;
        while !learned && std::time::Instant::now() < deadline {
            // SAFETY: libc read into a live buffer; the group is non-blocking.
            let read = unsafe { libc::read(raw, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if read > 0 {
                let chunk = buf[..read as usize].to_vec();
                assert!(ctx.process_read(&chunk, super::SendWindow::Live).0);
            } else {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    super::LearnMsg::Candidate(candidate) => {
                        learned |= candidate.display_path.ends_with("libshed.so");
                    }
                    super::LearnMsg::QueueOverflow => {
                        panic!("the unlimited queue never overflows in the kernel")
                    }
                    _ => {}
                }
            }
        }
        assert!(learned, "a provider opened after the shed is still learned");
    }

    /// Live stop-tail proof (privileged): with no drain thread, 2600
    /// negative opens followed by one provider open queue a snapshot;
    /// `drain_final_tail` must decide the whole snapshot — the provider
    /// opened last is reported and every queued event is counted. A tail
    /// that stops early (a byte/event unit error) drops the last quarter,
    /// including the provider. Run with `sudo -n` (fanotify needs
    /// `CAP_SYS_ADMIN`).
    #[test]
    #[ignore = "needs CAP_SYS_ADMIN fanotify group"]
    fn learn_live_final_tail_decides_queued_snapshot() {
        use std::os::unix::io::AsRawFd;
        let dir = tempfile::tempdir().unwrap();
        for index in 0..2600 {
            std::fs::write(dir.path().join(format!("f{index}")), b"not elf").unwrap();
        }
        let c = dir.path().join("tailsnap.c");
        let so = dir.path().join("libtailsnap.so");
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
        let (mut learner, rx) = super::FileLearner::start().expect("fanotify group (run as root)");
        // Never begin the drain: this thread queues the snapshot, then
        // decides exactly it through the stop-tail path.
        let super::PendingArming {
            group,
            tx,
            fionread_unit,
            fionread_exact,
            ..
        } = learner.pending.take().expect("armed learner");
        let raw = group.as_raw_fd();
        assert!(
            std::process::Command::new("sh")
                .args(["-c", "cat \"$1\"/f* > /dev/null", "sh"])
                .arg(dir.path())
                .status()
                .unwrap()
                .success()
        );
        assert!(
            std::process::Command::new("cat")
                .arg(&so)
                .stdout(std::process::Stdio::null())
                .status()
                .unwrap()
                .success()
        );
        let queued = super::queued_event_bytes(raw).expect("FIONREAD");
        let state = std::sync::Arc::new(super::LearnShutdownState::default());
        let mut ctx = super::DrainCtx {
            group: raw,
            tx: &tx,
            state: &state,
            self_pid: std::process::id(),
            fionread_unit,
            fionread_exact,
            cache: super::LearnCache::new(),
            stats: super::DrainStats::default(),
            ignore_marks: 0,
            marked_this_period: std::collections::HashSet::new(),
        };
        let mut buf = vec![0u8; 64 * 1024];
        assert!(
            super::drain_final_tail(raw, &mut ctx, &mut buf),
            "the snapshot tail is decided within the bound (queued {queued} bytes)"
        );
        let mut seen = false;
        let mut overflow = false;
        while let Ok(msg) = rx.try_recv() {
            match msg {
                super::LearnMsg::Candidate(candidate) => {
                    seen |= candidate.display_path.ends_with("libtailsnap.so");
                }
                super::LearnMsg::QueueOverflow => overflow = true,
                _ => {}
            }
        }
        assert!(
            !overflow,
            "the unlimited queue never overflows in the kernel"
        );
        assert!(
            seen,
            "the provider opened last is reported (queued {queued} bytes, {} events decided)",
            ctx.stats.events
        );
        assert!(
            ctx.stats.events >= 2601,
            "the whole snapshot is decided, not a prefix: {} events for {queued} queued bytes",
            ctx.stats.events
        );
    }

    /// Live ignore-mark proof (privileged): a file proved negative stops
    /// reporting opens once ignore-marked, and the periodic flush makes
    /// its next open report again — the bound that re-proves a file
    /// changed without a modification event (a shared writable mapping).
    /// Run with `sudo -n` (fanotify needs `CAP_SYS_ADMIN`).
    #[test]
    #[ignore = "needs CAP_SYS_ADMIN fanotify group"]
    fn learn_live_ignore_mark_filters_until_flush() {
        use std::os::unix::io::AsRawFd;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("negative.dat");
        std::fs::write(&path, b"not elf").unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let target = super::file_identity(&file).unwrap();
        let (mut learner, _rx) = super::FileLearner::start().expect("fanotify group (run as root)");
        let super::PendingArming { group, .. } = learner.pending.take().expect("armed learner");
        let raw = group.as_raw_fd();
        let open_by_child = || {
            assert!(
                std::process::Command::new("cat")
                    .arg(&path)
                    .stdout(std::process::Stdio::null())
                    .status()
                    .unwrap()
                    .success()
            );
        };
        let window = std::time::Duration::from_millis(300);
        // Healthy twin: unmarked, the child's open is reported.
        open_by_child();
        assert!(
            read_events_for(raw, target, window).0,
            "an unmarked open is reported"
        );
        assert!(
            super::ignore_negative_inode(raw, &file),
            "ignore mark accepted"
        );
        open_by_child();
        assert!(
            !read_events_for(raw, target, window).0,
            "an ignored open is filtered"
        );
        assert!(super::flush_ignore_marks(raw), "flush accepted");
        open_by_child();
        assert!(
            read_events_for(raw, target, window).0,
            "after the flush the open reports again"
        );
    }

    /// Live ignore-mark proof (privileged): each proved-negative
    /// generation is marked at most once per flush period (re-marking
    /// the same file does not recount), and a file that moves between
    /// its proof and its mark has the mark removed again and is never
    /// cached as negative — its next open re-proves the new content.
    /// Run with `sudo -n` (fanotify needs `CAP_SYS_ADMIN`).
    #[test]
    #[ignore = "needs CAP_SYS_ADMIN fanotify group"]
    fn learn_live_ignore_mark_counts_once_and_rechecks_the_race() {
        use std::os::unix::io::AsRawFd;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("negative.dat");
        std::fs::write(&path, b"not elf").unwrap();
        let (mut learner, _rx) = super::FileLearner::start().expect("fanotify group (run as root)");
        let super::PendingArming { group, tx, .. } = learner.pending.take().expect("armed learner");
        let raw = group.as_raw_fd();
        let state = std::sync::Arc::new(super::LearnShutdownState::default());
        let mut ctx = super::DrainCtx {
            group: raw,
            tx: &tx,
            state: &state,
            self_pid: std::process::id(),
            fionread_unit: super::FANOTIFY_META_LEN,
            fionread_exact: true,
            cache: super::LearnCache::new(),
            stats: super::DrainStats::default(),
            ignore_marks: 0,
            marked_this_period: std::collections::HashSet::new(),
        };
        // Healthy twin: a fresh negative is marked once and cached.
        let file = std::fs::File::open(&path).unwrap();
        let generation = super::file_generation(&file).unwrap();
        ctx.note_negative(generation, &file);
        assert_eq!(ctx.ignore_marks, 1, "the first mark counts once");
        assert!(
            !ctx.cache.needs_check(generation),
            "a marked negative is cached"
        );
        // Re-marking the same generation within the period recounts
        // nothing.
        let outcome = ctx.mark_ignored_for(generation, &file);
        assert_eq!(
            outcome,
            super::IgnoreMarkOutcome::Refused,
            "already marked this period"
        );
        assert_eq!(
            ctx.ignore_marks, 1,
            "a re-mark within the period does not recount"
        );
        // A file that moves under its proof is neither cached nor left
        // marked: the generation is captured, the file is rewritten to
        // a new size, and only then is the stale proof recorded.
        let path2 = dir.path().join("raced.dat");
        std::fs::write(&path2, b"not elf either").unwrap();
        let file2 = std::fs::File::open(&path2).unwrap();
        let stale = super::file_generation(&file2).unwrap();
        std::fs::write(&path2, b"not elf either, but longer now").unwrap();
        ctx.note_negative(stale, &file2);
        assert!(
            ctx.cache.needs_check(stale),
            "a raced file is never cached negative"
        );
        assert_eq!(ctx.ignore_marks, 1, "a raced mark is removed, not counted");
        let fresh = super::file_generation(&file2).unwrap();
        assert_ne!(
            (fresh.2, fresh.3, fresh.4),
            (stale.2, stale.3, stale.4),
            "the race moved size+ctime"
        );
        assert!(
            ctx.cache.needs_check(fresh),
            "the new generation still needs its proof"
        );
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

    /// Duplicates `fd` onto the first free number at or above a high
    /// floor and closes the original: the kernel allocates the lowest
    /// free fd, so a just-closed low number can be reused by another
    /// test thread's open before the assert below observes it (flaked
    /// under load: `fcntl` read back 1, a reused CLOEXEC file, instead
    /// of `EBADF`). Test fds live low, so a high probe number is never
    /// reused and the close assert observes only this test. The floor
    /// derives from the soft `RLIMIT_NOFILE` (1024 where the limit
    /// allows, 16 below it where it does not), so the dup works under
    /// the common soft limit of 1024 as well as higher ones.
    fn dup_fd_high(fd: std::os::unix::io::RawFd) -> std::os::unix::io::RawFd {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit writes the struct on success.
        let floor: libc::c_int = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } == 0 {
            // Below 1024 the floor must clear the soft limit (fd numbers
            // run below it), while staying high enough to avoid test fds.
            1024u64.min(lim.rlim_cur.saturating_sub(16)) as libc::c_int
        } else {
            1024
        };
        // SAFETY: fcntl dup of a live fd; the floor is within limits.
        let high = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, floor) };
        assert!(
            high >= floor,
            "the probe dup must clear the test fd range, got {high} for floor {floor}"
        );
        // SAFETY: close of the original, now duplicated, fd.
        unsafe {
            libc::close(fd);
        }
        high
    }

    /// The unread tail of an already-read buffer closes its fds: an
    /// early drain exit must not leak the event fds and pidfds the
    /// kernel installed for records past the break.
    #[test]
    fn learn_unread_tail_closes_event_and_pid_fds() {
        use std::os::unix::io::IntoRawFd;
        let tail_fd = dup_fd_high(std::fs::File::open("/bin/sh").unwrap().into_raw_fd());
        let tail_pidfd = dup_fd_high(std::fs::File::open("/bin/sh").unwrap().into_raw_fd());
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
