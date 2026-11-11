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

use std::collections::HashMap;
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
    /// A periodic re-mark found no marked filesystem (for example the
    /// post-setup capability shed took `CAP_SYS_ADMIN`): learning is
    /// degraded from here, filed once as a named gap.
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

/// Mount points to mark, parsed from `/proc/self/mountinfo` text:
/// field 5 is the mount point, the field after `" - "` is the fstype.
/// Malformed lines are skipped; escapes (`\040` etc.) are decoded.
/// Paths stay byte-exact (`PathBuf`): a lossy string could miss a mark.
pub(crate) fn mount_points_for_marks(mountinfo: &str) -> Vec<std::path::PathBuf> {
    let mut points = Vec::new();
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
        if point.as_os_str().is_empty() || points.contains(&point) {
            continue;
        }
        points.push(point);
    }
    points
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
    /// Group + sender held between arming and `begin_drain`: the
    /// reader thread spawns post-shed so it never retains the
    /// transient startup `CAP_SYS_ADMIN` (capabilities are
    /// per-thread). `None` once the drain runs.
    pending: Option<(OwnedFd, SyncSender<LearnMsg>)>,
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
        let (marked, skipped) = mark_all_filesystems(&group);
        if marked == 0 {
            return Err(LearnAbsent {
                reason: format!("no filesystem could be marked ({skipped} skipped)"),
            });
        }
        if crate::run::capture_diagnostics_on() {
            eprintln!(
                "p11scope: file learning active: {marked} filesystems marked ({skipped} skipped)"
            );
        }
        let (tx, rx) = std::sync::mpsc::sync_channel(LEARN_CHANNEL_DEPTH);
        let state = Arc::new(LearnShutdownState::default());
        Ok((
            Self {
                state,
                thread: None,
                pending: Some((group, tx)),
            },
            rx,
        ))
    }

    /// Spawns the reader thread with the caller's current capability
    /// sets (post-shed). Idempotent. Re-marking from the drain may
    /// fail without `CAP_SYS_ADMIN`; the initial marks keep
    /// delivering, and the drain files unavailable only when no
    /// event proves the marks alive (its existing blind check).
    pub(crate) fn begin_drain(&mut self) -> Result<(), LearnAbsent> {
        if self.thread.is_some() {
            return Ok(());
        }
        let Some((group, tx)) = self.pending.take() else {
            return Ok(());
        };
        let worker_state = Arc::clone(&self.state);
        match std::thread::Builder::new()
            .name("p11scope-learn".to_string())
            .spawn(move || drain_loop(group, tx, worker_state))
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

/// Marks every real filesystem from the observer's mount table. Returns
/// `(marked, skipped)`: per-mount failures are tolerated, an unreadable
/// table falls back to `/` alone.
fn mark_all_filesystems(group: &OwnedFd) -> (usize, usize) {
    use std::os::unix::ffi::OsStrExt;
    const MOUNTINFO_CAP: usize = 1024 * 1024;
    let text = std::fs::read_to_string("/proc/self/mountinfo")
        .ok()
        .filter(|text| text.len() <= MOUNTINFO_CAP);
    let points = text
        .as_deref()
        .map(mount_points_for_marks)
        .filter(|points| !points.is_empty())
        .unwrap_or_else(|| vec![std::path::PathBuf::from("/")]);
    let mut marked = 0usize;
    let mut skipped = 0usize;
    for point in &points {
        let Ok(path) = std::ffi::CString::new(point.as_os_str().as_bytes()) else {
            skipped += 1;
            continue;
        };
        // SAFETY: libc call; the group fd and NUL-terminated path are valid.
        let rc = unsafe {
            libc::fanotify_mark(
                group.as_raw_fd(),
                libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
                libc::FAN_OPEN,
                libc::AT_FDCWD,
                path.as_ptr(),
            )
        };
        if rc == 0 {
            marked += 1;
        } else {
            skipped += 1;
        }
    }
    (marked, skipped)
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
fn drain_loop(group: OwnedFd, tx: SyncSender<LearnMsg>, state: Arc<LearnShutdownState>) {
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
    let mut events_at_last_remark = 0u64;
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
            let (marked, _) = mark_all_filesystems(&group);
            // A failed re-mark alone does not prove learning stopped:
            // the initial marks survive a capability shed and keep
            // delivering. Only when no event arrived since the last
            // re-mark either is the drain really blind.
            let blind = stats.events == events_at_last_remark;
            events_at_last_remark = stats.events;
            if marked == 0 && blind && !unavailable_sent {
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
                mark_all_filesystems(&group);
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
        let mut marks: Vec<String> = super::mount_points_for_marks(table)
            .iter()
            .map(|point| point.to_string_lossy().into_owned())
            .collect();
        marks.sort();
        assert_eq!(marks, vec!["/", "/dev", "/mnt/ovl", "/mnt/with space"]);
    }

    /// A failed re-mark of an already covered filesystem is not a
    /// coverage loss: the startup mark survives the capability shed
    /// and keeps delivering, so post-shed add failures on retained
    /// filesystems file no gap.
    #[test]
    fn learn_retained_mark_failure_is_not_a_coverage_gap() {
        let covered: std::collections::BTreeSet<std::path::PathBuf> =
            ["/", "/data"].iter().map(std::path::PathBuf::from).collect();
        let visible: Vec<std::path::PathBuf> = covered.iter().cloned().collect();
        // Every add fails now (no CAP_SYS_ADMIN after the shed).
        let (next, uncovered) = super::evaluate_mark_coverage(&covered, &visible, |_| false);
        assert_eq!(uncovered, 0, "retained marks stay covered");
        assert_eq!(next, covered);
    }

    /// A newly mounted filesystem whose mark fails is uncovered even
    /// while older filesystems keep delivering: coverage comes from
    /// the retained-mark set, never from traffic elsewhere.
    #[test]
    fn learn_failed_new_filesystem_mark_is_uncovered() {
        let covered: std::collections::BTreeSet<std::path::PathBuf> =
            ["/"].iter().map(std::path::PathBuf::from).collect();
        let visible = vec![
            std::path::PathBuf::from("/"),
            std::path::PathBuf::from("/mnt/new"),
        ];
        let (next, uncovered) = super::evaluate_mark_coverage(&covered, &visible, |_| false);
        assert_eq!(uncovered, 1, "the unmarked new filesystem is a gap");
        assert_eq!(next, covered, "only the retained filesystem is covered");
    }

    /// A newly mounted filesystem that marks successfully joins the
    /// covered set with no gap.
    #[test]
    fn learn_successful_new_filesystem_mark_covers_it() {
        let covered: std::collections::BTreeSet<std::path::PathBuf> =
            ["/"].iter().map(std::path::PathBuf::from).collect();
        let visible = vec![
            std::path::PathBuf::from("/"),
            std::path::PathBuf::from("/mnt/new"),
        ];
        let (next, uncovered) =
            super::evaluate_mark_coverage(&covered, &visible, |point| {
                point.as_os_str() == "/mnt/new"
            });
        assert_eq!(uncovered, 0);
        assert!(next.contains(std::path::Path::new("/mnt/new")));
        assert!(next.contains(std::path::Path::new("/")));
    }

    /// With nothing retained, every failed mark is uncovered (the
    /// startup shape behind the unavailable-learning refusal).
    #[test]
    fn learn_no_retained_marks_counts_every_failure() {
        let covered = std::collections::BTreeSet::new();
        let visible = vec![
            std::path::PathBuf::from("/"),
            std::path::PathBuf::from("/data"),
        ];
        let (next, uncovered) = super::evaluate_mark_coverage(&covered, &visible, |_| false);
        assert_eq!(uncovered, 2);
        assert!(next.is_empty());
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
