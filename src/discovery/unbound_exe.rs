//! SPDX-License-Identifier: GPL-3.0-or-later
//! Userspace executable resolution for unidentified caller images.
//!
//! The coordinator joins each unidentified image's domain-tagged task
//! cookie to the EXEC record's ticket (never a bare PID) and keeps
//! the EXEC's `(dev, ino)` pair per image. This resolver turns that
//! pair into a path, in order: (a) a still-live `/proc/<pid>/exe`
//! whose start time predates the EXEC, (b) an exe identity the scan
//! already learned from an admitted caller, (c) a lazy bounded
//! cached index of fixed system binary dirs, else (d) unknown with
//! its reason. The EXEC pair lives in the mapped-device domain, so
//! every candidate is verified by matching `(dev, ino)` there (a
//! private one-page mapping read back from our own maps), never by
//! stat alone. No argv, environ, key, PIN, or payload is ever read.

use crate::discovery::caller_registry::{ExeIdentity, ExeResolution, UnboundExe};
use p11scope_manifest::maps::Device;
use std::collections::HashMap;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

/// Fixed system binary dirs for source (c): never the user's PATH
/// or environment. `/usr/libexec` is additionally indexed one level
/// below it.
pub(crate) const SYSTEM_BINARY_DIRS: [&str; 7] = [
    "/usr/bin",
    "/usr/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/bin",
    "/sbin",
    "/usr/libexec",
];

/// The one root indexed an extra level below it.
const LIBEXEC_SUBDIR_ROOT: &str = "/usr/libexec";

/// LIM-1: the system index never holds more entries than this;
/// measured 5,675 stat-able entries across the fixed roots on the
/// build host (~60 ms to walk), so the cap carries an order of
/// magnitude of headroom and is never lowered.
pub(crate) const DEFAULT_MAX_SYSTEM_INDEX_ENTRIES: usize = 65_536;

/// The index rebuilds at most this often.
const INDEX_REFRESH_WINDOW_NS: u64 = 5_000_000_000;

/// Live-process reads for source (a): exactly the pid's start time
/// and exe identity, nothing else.
pub(crate) struct ProcReads<'a> {
    pub start_time: Box<dyn Fn(u32) -> Option<u64> + 'a>,
    pub exe_identity: Box<dyn Fn(u32) -> Option<ExeIdentity> + 'a>,
    /// False under pidns numbering mismatch, incomparable clocks,
    /// or boottime skew: (a) is skipped, never guessed.
    pub trusted: bool,
    pub mono_now: Option<u64>,
    pub boot_now: Option<u64>,
    pub tick_ns: u64,
}

/// A maps-domain `(dev, ino)` probe for learned paths: the
/// scripted closure in tests, the mapping probe in production.
type VerifyProbe<'a> = Box<dyn Fn(&str) -> Option<(u64, u64)> + 'a>;

/// The canonical spelling of a verified path for dedupe: the
/// canonicalized path, so a merged-`/usr` `/bin/x` vs `/usr/bin/x`
/// pair names one file. A path that verified moments ago but no
/// longer canonicalizes (deleted under us) stays its own
/// candidate under its raw spelling.
fn canonical_spelling(path: &str) -> String {
    std::fs::canonicalize(path)
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string())
}

/// Distinct verified spellings by canonical path (the sorted-first
/// spelling kept per file), sorted for a stable order.
fn dedupe_canonical(paths: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut distinct: Vec<String> = paths
        .into_iter()
        .filter(|path| seen.insert(canonical_spelling(path)))
        .collect();
    distinct.sort();
    distinct
}

/// Open `path` for the mapping probe: close-on-exec, never a
/// controlling terminal, never following a final-component symlink,
/// never blocking on a FIFO or device open. A symlink (however
/// benign), a FIFO, a device, or anything unopenable fails closed
/// here, before any identity read — a path swapped in under a
/// user-writable dir can neither redirect the probe nor hang the
/// root observer.
fn open_probe(path: &str) -> Option<std::fs::File> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)
        .ok()
}

/// Open one `/proc/<pid>/exe` link for source (a): the same safe
/// open minus `O_NOFOLLOW`, because the path itself is a
/// kernel-managed symlink the kernel always resolves to the
/// process's real executable — never to a user-controlled target.
/// Any other shape is refused: only `/proc/<digits>/exe` resolves
/// here.
fn open_proc_exe_link(path: &str) -> Option<std::fs::File> {
    let pid = path.strip_prefix("/proc/")?.strip_suffix("/exe")?;
    if pid.is_empty() || !pid.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)
        .ok()
}

/// The maps-domain identity of one path: privately map its first
/// page and read the mapping's `(dev, ino)` from our own maps (no
/// capability needed for our own mappings). This is the device
/// domain the kernel's EXEC pair lives in (`i_sb->s_dev`): on btrfs
/// it differs from `stat`'s subvolume device, so stat alone can
/// never confirm an EXEC pair there. Fail-closed: any failure
/// (unopenable, symlink, non-regular, empty, unmappable,
/// unparsable) is `None`. Content is never read — the page is
/// mapped, never touched.
pub(crate) fn real_maps_identity(path: &str) -> Option<(u64, u64)> {
    let file = open_probe(path)?;
    maps_identity_of_open_file(&file)
}

/// Source (a): the maps-domain identity of a live process's own
/// executable, probed by opening its `/proc/<pid>/exe` link itself —
/// never by opening the readlink target, which a user-writable dir
/// could swap for a FIFO or a device between the link read and the
/// open. Only `/proc/<digits>/exe` paths resolve here.
pub(crate) fn real_maps_identity_proc_exe_link(path: &str) -> Option<(u64, u64)> {
    let file = open_proc_exe_link(path)?;
    maps_identity_of_open_file(&file)
}

/// The shared probe tail: `fstat` regularity (a real page to map)
/// gates the private one-page mapping, whose `(dev, ino)` reads back
/// from our own maps.
fn maps_identity_of_open_file(file: &std::fs::File) -> Option<(u64, u64)> {
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() == 0 {
        return None;
    }
    let page = 4096usize;
    // SAFETY: length is nonzero, the fd is open, the offset is 0;
    // the mapping is never accessed, only looked up in our own maps.
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ,
            libc::MAP_PRIVATE,
            std::os::fd::AsRawFd::as_raw_fd(file),
            0,
        )
    };
    if addr == libc::MAP_FAILED {
        return None;
    }
    let addr = addr as u64;
    let found = std::fs::read_to_string("/proc/self/maps")
        .ok()
        .and_then(|maps| maps_identity_at(&maps, addr));
    // SAFETY: the exact pair of the mmap above.
    unsafe {
        libc::munmap(addr as *mut libc::c_void, page);
    }
    found
}

/// Parse our own maps for the mapping covering `addr`: `(dev, ino)`
/// with the device reconstructed from the hex major:minor pair
/// through the one shared kernel encode ([`Device::to_kdev`]), so the
/// pair compares like for like with the kernel's raw `s_dev` word.
/// `libc::makedev` builds the userspace `st_dev` layout instead and
/// must never meet a maps pair. Malformed lines are skipped, never fatal.
fn maps_identity_at(maps: &str, addr: u64) -> Option<(u64, u64)> {
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let (Some(range), Some(_perms), Some(_offset), Some(dev), Some(ino)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
        else {
            continue;
        };
        if !(start <= addr && addr < end) {
            continue;
        }
        let Some((major, minor)) = dev.split_once(':') else {
            continue;
        };
        let (Ok(major), Ok(minor)) = (
            u32::from_str_radix(major, 16),
            u32::from_str_radix(minor, 16),
        ) else {
            continue;
        };
        let Ok(ino) = ino.parse::<u64>() else {
            continue;
        };
        let device = Device {
            major: u64::from(major),
            minor: u64::from(minor),
        };
        return Some((device.to_kdev(), ino));
    }
    None
}

/// Scan-learned identities for source (b): maps-domain
/// `(dev, ino)` to path, re-verified by the mapping probe at use.
/// `all_by_identity` carries every learned spelling per pair when
/// the teacher set is known (production); `None` means exactly
/// `by_identity` (scripted single-path tests).
pub(crate) struct ScanLearned<'a> {
    pub by_identity: &'a HashMap<(u64, u64), String>,
    pub verify: VerifyProbe<'a>,
    pub all_by_identity: Option<&'a HashMap<(u64, u64), Vec<String>>>,
}

/// Lazy system-binary index plus resolution.
pub(crate) struct ExeResolver {
    cap: usize,
    /// Candidates by ino (walk order per bucket): the lookup
    /// confirms each candidate's mapped `(dev, ino)`, so a host
    /// whose stat and mapped devices differ still resolves.
    entries: HashMap<u64, Vec<String>>,
    /// Indexed paths (the unit the cap bounds).
    paths: usize,
    built_at: Option<u64>,
    /// Builds so far (test-observed; production keeps the count so
    /// the lazy-build policy stays measurable).
    #[allow(dead_code)]
    builds: u64,
    /// Entries shed past the cap, sticky (test-observed).
    #[allow(dead_code)]
    shed: u64,
    clock: fn() -> Option<u64>,
    #[cfg(test)]
    index_dirs: Option<Vec<PathBuf>>,
    #[cfg(test)]
    now_override: Option<u64>,
    /// Scripted maps-domain answers by path (strict when set).
    #[cfg(test)]
    maps_override: Option<HashMap<String, (u64, u64)>>,
}

impl ExeResolver {
    pub(crate) fn new() -> Self {
        Self {
            cap: DEFAULT_MAX_SYSTEM_INDEX_ENTRIES,
            entries: HashMap::new(),
            paths: 0,
            built_at: None,
            builds: 0,
            shed: 0,
            clock: crate::attach::monotonic_ns,
            #[cfg(test)]
            index_dirs: None,
            #[cfg(test)]
            now_override: None,
            #[cfg(test)]
            maps_override: None,
        }
    }

    /// Resolve one EXEC-joined `(dev, ino)` pair to a path: a live
    /// link, a scan record, the system index, else unknown with its
    /// reason. A `(0, 0)` pair reads unavailable without any read.
    pub(crate) fn resolve(
        &mut self,
        pid: u32,
        dev: u64,
        ino: u64,
        hook_ts_ns: u64,
        proc: &ProcReads<'_>,
        scan: &ScanLearned<'_>,
    ) -> UnboundExe {
        if dev == 0 && ino == 0 {
            return UnboundExe {
                dev,
                ino,
                path: None,
                resolution: ExeResolution::ExeUnavailable,
                identity_candidates: Vec::new(),
            };
        }
        if let Some(path) = Self::via_live_process(pid, dev, ino, hook_ts_ns, proc) {
            return UnboundExe {
                dev,
                ino,
                identity_candidates: vec![path.clone()],
                path: Some(path),
                resolution: ExeResolution::ProcAlive,
            };
        }
        // Sources (b) and (c) pool their verified spellings: the
        // shown path is the sorted-first verified spelling, learned
        // preferred over index; every distinct canonical spelling
        // lists as a candidate, sorted. One candidate reads
        // unambiguous; two or more keep the shown path and read
        // ambiguous, never unknown.
        let learned = Self::scan_learned_hits(dev, ino, scan);
        let indexed = self.system_index_hits(dev, ino);
        let mut seen = std::collections::HashSet::new();
        let mut candidates = Vec::new();
        for path in learned.iter().chain(indexed.iter()) {
            if seen.insert(canonical_spelling(path)) {
                candidates.push(path.clone());
            }
        }
        candidates.sort();
        let (path, resolution) = match (learned.first(), indexed.first()) {
            (Some(path), _) => (path, ExeResolution::ScanLearned),
            (None, Some(path)) => (path, ExeResolution::SystemIndex),
            (None, None) => {
                return UnboundExe {
                    dev,
                    ino,
                    path: None,
                    resolution: ExeResolution::PathUnknown,
                    identity_candidates: Vec::new(),
                };
            }
        };
        UnboundExe {
            dev,
            ino,
            path: Some(path.clone()),
            resolution,
            identity_candidates: candidates,
        }
    }

    /// Source (a): the pid is alive, its start tick predates the
    /// EXEC (boottime domain, suspend-tolerant), and its live
    /// maps-domain exe identity equals the joined pair. A reused
    /// pid reads a start after the EXEC and is never used. Only the
    /// start time and the exe identity are read — no cwd, cmdline,
    /// or environ.
    fn via_live_process(
        pid: u32,
        dev: u64,
        ino: u64,
        hook_ts_ns: u64,
        proc: &ProcReads<'_>,
    ) -> Option<String> {
        if !proc.trusted {
            return None;
        }
        let (mono_now, boot_now) = match (proc.mono_now, proc.boot_now) {
            (Some(mono), Some(boot)) => (mono, boot),
            _ => return None,
        };
        // The kernel floors the start tick, so `start * tick` is a
        // lower bound on the birth; the EXEC instant is estimated in
        // the boottime domain with the currently observed suspend
        // slack. The slack only grows after the EXEC, so the
        // estimate only grows with it: a start provably after the
        // EXEC is a different generation and refuses exactly, while
        // admission widens over a suspended capture. Residual: a
        // reuse within one tick plus later suspend, with the same
        // binary, still alive — the `(dev, ino)` equality below is
        // the second factor.
        let start = (proc.start_time)(pid)?;
        let slack = boot_now.saturating_sub(mono_now);
        let est = hook_ts_ns.saturating_add(slack);
        if start.saturating_mul(proc.tick_ns) > est {
            return None;
        }
        let live = (proc.exe_identity)(pid)?;
        if live.dev != dev || live.ino != ino {
            return None;
        }
        live.path
    }

    /// Source (b): every spelling the scan learned for this
    /// maps-domain `(dev, ino)` — the primary plus every known
    /// teacher spelling — re-verified by the mapping probe (a
    /// replaced file refuses), distinct by canonical path, sorted.
    fn scan_learned_hits(dev: u64, ino: u64, scan: &ScanLearned<'_>) -> Vec<String> {
        let mut spellings = Vec::new();
        if let Some(path) = scan.by_identity.get(&(dev, ino)) {
            spellings.push(path.clone());
        }
        if let Some(all) = scan.all_by_identity
            && let Some(paths) = all.get(&(dev, ino))
        {
            spellings.extend(paths.iter().cloned());
        }
        // The primary usually lists among the known spellings too:
        // each distinct spelling verifies once.
        spellings.sort();
        spellings.dedup();
        let verified: Vec<String> = spellings
            .into_iter()
            .filter(|path| (scan.verify)(path).is_some_and(|pair| pair == (dev, ino)))
            .collect();
        dedupe_canonical(verified)
    }

    /// Source (c): the lazy system index. Every same-ino candidate
    /// is confirmed against the joined pair in the mapped device
    /// domain (a deleted or replaced binary refuses, as does a
    /// stat-only pair on a split-device host); hits list distinct
    /// by canonical path, sorted.
    fn system_index_hits(&mut self, dev: u64, ino: u64) -> Vec<String> {
        self.refresh_index_if_stale();
        let Some(candidates) = self.entries.get(&ino) else {
            return Vec::new();
        };
        let verified: Vec<String> = candidates
            .iter()
            .filter(|path| {
                self.maps_identity_of(path)
                    .is_some_and(|pair| pair == (dev, ino))
            })
            .cloned()
            .collect();
        dedupe_canonical(verified)
    }

    /// The maps-domain identity of one indexed path: the scripted
    /// answer in tests when set (strict: an unscripted path reads
    /// `None`), else the mapping probe.
    fn maps_identity_of(&self, path: &str) -> Option<(u64, u64)> {
        #[cfg(test)]
        if let Some(answers) = &self.maps_override {
            return answers.get(path).copied();
        }
        real_maps_identity(path)
    }

    /// Build the index on the first miss, then at most every few
    /// seconds. Without a clock the cache is kept, never
    /// rebuild-looped.
    fn refresh_index_if_stale(&mut self) {
        if self.built_at.is_some() {
            match (self.built_at, self.now_ns()) {
                (Some(built), Some(now)) if now.saturating_sub(built) < INDEX_REFRESH_WINDOW_NS => {
                    return;
                }
                (_, None) => return,
                _ => {}
            }
        }
        self.rebuild();
    }

    fn now_ns(&self) -> Option<u64> {
        #[cfg(test)]
        if let Some(now) = self.now_override {
            return Some(now);
        }
        (self.clock)()
    }

    /// Walk the fixed roots (sorted, so same-ino candidates keep
    /// walk order), skipping final-component symlinks and
    /// non-files, bounded by the cap. Unreadable roots shed
    /// silently: the index is a hint, and a miss degrades to
    /// unknown, never to an error.
    fn rebuild(&mut self) {
        self.builds += 1;
        self.entries.clear();
        self.paths = 0;
        for dir in self.index_dirs() {
            if self.paths >= self.cap {
                break;
            }
            self.index_dir(&dir, 0);
        }
        self.built_at = Some(self.now_ns().unwrap_or(0));
    }

    fn index_dir(&mut self, dir: &Path, depth: usize) {
        let mut names: Vec<PathBuf> = match std::fs::read_dir(dir) {
            Ok(read) => read
                .filter_map(|entry| entry.ok().map(|entry| entry.path()))
                .collect(),
            Err(_) => return,
        };
        names.sort();
        for path in &names {
            // Final-component symlinks are never indexed: the
            // confirmation probe opens with O_NOFOLLOW and would
            // refuse them, so indexing them only spends cap and
            // probes on dead candidates.
            match std::fs::symlink_metadata(path) {
                Ok(link) if link.is_symlink() => continue,
                Ok(_) => {}
                Err(_) => continue,
            }
            let meta = match std::fs::metadata(path) {
                Ok(meta) => meta,
                Err(_) => continue,
            };
            if !meta.is_file() {
                continue;
            }
            if self.paths >= self.cap {
                self.shed = self.shed.saturating_add(1);
                continue;
            }
            self.paths += 1;
            self.entries
                .entry(meta.ino())
                .or_default()
                .push(path.to_string_lossy().into_owned());
        }
        if depth == 0 && dir == Path::new(LIBEXEC_SUBDIR_ROOT) {
            for path in &names {
                if self.paths >= self.cap {
                    break;
                }
                if path.is_dir() {
                    self.index_dir(path, 1);
                }
            }
        }
    }

    fn index_dirs(&self) -> Vec<PathBuf> {
        #[cfg(test)]
        if let Some(dirs) = &self.index_dirs {
            return dirs.clone();
        }
        SYSTEM_BINARY_DIRS.iter().map(PathBuf::from).collect()
    }

    /// Test-only index root override (production always indexes the
    /// fixed system list).
    #[cfg(test)]
    pub(crate) fn set_index_dirs(&mut self, dirs: Vec<PathBuf>) {
        self.index_dirs = Some(dirs);
    }

    /// Test-only index entry cap.
    #[cfg(test)]
    pub(crate) fn set_index_cap(&mut self, cap: usize) {
        self.cap = cap;
    }

    /// Test-only clock override (nanoseconds, monotonic).
    #[cfg(test)]
    pub(crate) fn set_now(&mut self, now_ns: u64) {
        self.now_override = Some(now_ns);
    }

    /// Test-only scripted maps-domain answers by path: the split
    /// stat/maps devices of a btrfs-style host, or any mapped
    /// identity. Strict when set: an unscripted path reads `None`.
    #[cfg(test)]
    pub(crate) fn set_scripted_maps_identities(&mut self, answers: HashMap<String, (u64, u64)>) {
        self.maps_override = Some(answers);
    }

    /// Index builds so far.
    #[cfg(test)]
    pub(crate) fn index_builds(&self) -> u64 {
        self.builds
    }

    /// Indexed entries.
    #[cfg(test)]
    pub(crate) fn index_len(&self) -> usize {
        self.paths
    }

    /// Entries shed past the cap, sticky.
    #[cfg(test)]
    pub(crate) fn index_shed(&self) -> u64 {
        self.shed
    }
}

impl Default for ExeResolver {
    fn default() -> Self {
        Self::new()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const TICK_NS: u64 = 10_000_000;

    /// The kernel word for `fstat` metadata: major/minor through the
    /// shared encode, so staged EXEC pairs live in the mapped domain
    /// like every real EXEC pair.
    fn kdev_of(meta: &std::fs::Metadata) -> u64 {
        Device {
            major: u64::from(libc::major(meta.dev())),
            minor: u64::from(libc::minor(meta.dev())),
        }
        .to_kdev()
    }

    struct ScriptedProc {
        start: Option<u64>,
        exe: Option<ExeIdentity>,
        start_calls: Cell<usize>,
        exe_calls: Cell<usize>,
    }

    impl ScriptedProc {
        fn dead() -> Self {
            Self {
                start: None,
                exe: None,
                start_calls: Cell::new(0),
                exe_calls: Cell::new(0),
            }
        }

        fn live(start: u64, dev: u64, ino: u64, path: &str) -> Self {
            Self {
                start: Some(start),
                exe: Some(ExeIdentity {
                    dev,
                    ino,
                    mtime_secs: 0,
                    mtime_nanos: 0,
                    path: Some(path.to_string()),
                }),
                start_calls: Cell::new(0),
                exe_calls: Cell::new(0),
            }
        }

        fn reads(
            &self,
            trusted: bool,
            mono_now: Option<u64>,
            boot_now: Option<u64>,
        ) -> ProcReads<'_> {
            ProcReads {
                start_time: Box::new(|_| {
                    self.start_calls.set(self.start_calls.get() + 1);
                    self.start
                }),
                exe_identity: Box::new(|_| {
                    self.exe_calls.set(self.exe_calls.get() + 1);
                    self.exe.clone()
                }),
                trusted,
                mono_now,
                boot_now,
                tick_ns: TICK_NS,
            }
        }
    }

    struct ScriptedScan {
        map: HashMap<(u64, u64), String>,
        multi: HashMap<(u64, u64), Vec<String>>,
        verify_answers: HashMap<String, (u64, u64)>,
        verify_calls: Cell<usize>,
    }

    impl ScriptedScan {
        fn empty() -> Self {
            Self {
                map: HashMap::new(),
                multi: HashMap::new(),
                verify_answers: HashMap::new(),
                verify_calls: Cell::new(0),
            }
        }

        fn learned(&mut self, dev: u64, ino: u64, path: &str, verify: Option<(u64, u64)>) {
            self.map.insert((dev, ino), path.to_string());
            if let Some(pair) = verify {
                self.verify_answers.insert(path.to_string(), pair);
            }
        }

        /// Teach several spellings for one pair (a snapshot-clone
        /// collision): the first is also the primary map entry.
        fn learned_multi(&mut self, dev: u64, ino: u64, paths: &[&str]) {
            self.multi.insert(
                (dev, ino),
                paths.iter().map(|path| path.to_string()).collect(),
            );
            if let Some(first) = paths.first() {
                self.map.insert((dev, ino), first.to_string());
            }
            for path in paths {
                self.verify_answers.insert(path.to_string(), (dev, ino));
            }
        }

        fn scan(&self) -> ScanLearned<'_> {
            ScanLearned {
                by_identity: &self.map,
                verify: Box::new(|path| {
                    self.verify_calls.set(self.verify_calls.get() + 1);
                    self.verify_answers.get(path).copied()
                }),
                all_by_identity: if self.multi.is_empty() {
                    None
                } else {
                    Some(&self.multi)
                },
            }
        }
    }

    /// (a): a live process whose start predates the EXEC and whose
    /// maps-domain exe identity equals the joined pair resolves by
    /// its live link.
    #[test]
    fn live_process_with_matching_start_and_identity_resolves() {
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(Vec::new());
        let proc = ScriptedProc::live(100, 8, 99, "/bin/x");
        let scan = ScriptedScan::empty();
        let exe = resolver.resolve(
            7,
            8,
            99,
            2_000_000_000,
            &proc.reads(true, Some(3_000_000_000), Some(3_000_000_000)),
            &scan.scan(),
        );
        assert_eq!(
            exe,
            UnboundExe {
                dev: 8,
                ino: 99,
                path: Some("/bin/x".to_string()),
                resolution: ExeResolution::ProcAlive,
                identity_candidates: vec!["/bin/x".to_string()],
            }
        );
    }

    /// (a) PID reuse: a live different process (start after the EXEC)
    /// is never used, and resolution falls through to unknown.
    #[test]
    fn reused_pid_with_later_start_is_never_used() {
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(Vec::new());
        let proc = ScriptedProc::live(300, 8, 99, "/bin/x");
        let scan = ScriptedScan::empty();
        let exe = resolver.resolve(
            7,
            8,
            99,
            2_000_000_000,
            &proc.reads(true, Some(3_000_000_000), Some(3_000_000_000)),
            &scan.scan(),
        );
        assert_eq!(
            exe,
            UnboundExe {
                dev: 8,
                ino: 99,
                path: None,
                resolution: ExeResolution::PathUnknown,
                identity_candidates: Vec::new(),
            }
        );
    }

    /// (a): the start matches but the live exe differs (the process
    /// exec'd again): the live link is not the joined image.
    #[test]
    fn live_process_with_changed_identity_falls_through() {
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(Vec::new());
        let proc = ScriptedProc::live(100, 8, 1000, "/bin/other");
        let scan = ScriptedScan::empty();
        let exe = resolver.resolve(
            7,
            8,
            99,
            2_000_000_000,
            &proc.reads(true, Some(3_000_000_000), Some(3_000_000_000)),
            &scan.scan(),
        );
        assert_eq!(exe.resolution, ExeResolution::PathUnknown);
        assert_eq!((exe.dev, exe.ino, exe.path), (8, 99, None));
    }

    /// (a) is skipped without trusted clocks/numbering even when the
    /// numbers would match; the scan hit below still resolves.
    #[test]
    fn untrusted_proc_reads_skip_to_scan() {
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(Vec::new());
        let proc = ScriptedProc::live(100, 8, 99, "/bin/x");
        let mut scan = ScriptedScan::empty();
        scan.learned(8, 99, "/usr/bin/x", Some((8, 99)));
        let exe = resolver.resolve(
            7,
            8,
            99,
            2_000_000_000,
            &proc.reads(false, Some(3_000_000_000), Some(3_000_000_000)),
            &scan.scan(),
        );
        assert_eq!(
            exe,
            UnboundExe {
                dev: 8,
                ino: 99,
                path: Some("/usr/bin/x".to_string()),
                resolution: ExeResolution::ScanLearned,
                identity_candidates: vec!["/usr/bin/x".to_string()],
            }
        );
        assert_eq!(
            proc.start_calls.get(),
            0,
            "untrusted reads make no proc reads"
        );
        assert_eq!(
            proc.exe_calls.get(),
            0,
            "untrusted reads make no proc reads"
        );
    }

    /// (a) needs both clocks; without them the live process cannot
    /// be ordered against the EXEC.
    #[test]
    fn missing_clocks_skip_live_process() {
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(Vec::new());
        let proc = ScriptedProc::live(100, 8, 99, "/bin/x");
        let mut scan = ScriptedScan::empty();
        scan.learned(8, 99, "/usr/bin/x", Some((8, 99)));
        let exe = resolver.resolve(
            7,
            8,
            99,
            2_000_000_000,
            &proc.reads(true, None, Some(3_000_000_000)),
            &scan.scan(),
        );
        assert_eq!(exe.resolution, ExeResolution::ScanLearned);
    }

    /// (b): the process is gone but the scan learned the same
    /// maps-domain `(dev, ino)` from an admitted caller.
    #[test]
    fn scan_learned_hit_resolves_after_exit() {
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(Vec::new());
        let proc = ScriptedProc::dead();
        let mut scan = ScriptedScan::empty();
        scan.learned(8, 99, "/usr/bin/x", Some((8, 99)));
        let exe = resolver.resolve(
            7,
            8,
            99,
            2_000_000_000,
            &proc.reads(true, Some(3_000_000_000), Some(3_000_000_000)),
            &scan.scan(),
        );
        assert_eq!(
            exe,
            UnboundExe {
                dev: 8,
                ino: 99,
                path: Some("/usr/bin/x".to_string()),
                resolution: ExeResolution::ScanLearned,
                identity_candidates: vec!["/usr/bin/x".to_string()],
            }
        );
    }

    /// One learned spelling resolves unambiguously: the single
    /// candidate is the path, and the image is not ambiguous.
    #[test]
    fn single_learned_path_resolves_unambiguous() {
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(Vec::new());
        let proc = ScriptedProc::dead();
        let mut scan = ScriptedScan::empty();
        scan.learned(8, 99, "/usr/bin/x", Some((8, 99)));
        let exe = resolver.resolve(
            7,
            8,
            99,
            2_000_000_000,
            &proc.reads(true, Some(3_000_000_000), Some(3_000_000_000)),
            &scan.scan(),
        );
        assert_eq!(exe.resolution, ExeResolution::ScanLearned);
        assert_eq!(exe.path.as_deref(), Some("/usr/bin/x"));
        assert!(!exe.identity_ambiguous());
        assert_eq!(exe.identity_candidates, vec!["/usr/bin/x".to_string()]);
    }

    /// Two learned spellings for one pair (snapshot-clone
    /// collision): the caller keeps a shown path and the image
    /// reads ambiguous with both candidates.
    #[test]
    fn two_learned_paths_for_one_pair_resolve_ambiguous() {
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(Vec::new());
        let proc = ScriptedProc::dead();
        let mut scan = ScriptedScan::empty();
        scan.learned_multi(82, 257, &["/snap/a/tool", "/snap/b/tool"]);
        let exe = resolver.resolve(
            7,
            82,
            257,
            2_000_000_000,
            &proc.reads(true, Some(3_000_000_000), Some(3_000_000_000)),
            &scan.scan(),
        );
        assert_eq!(exe.resolution, ExeResolution::ScanLearned);
        assert!(
            exe.path.as_deref() == Some("/snap/a/tool")
                || exe.path.as_deref() == Some("/snap/b/tool"),
            "a colliding pair keeps a shown path: {exe:?}"
        );
        assert!(
            exe.identity_ambiguous(),
            "a colliding pair reads ambiguous: {exe:?}"
        );
        assert_eq!(
            exe.identity_candidates,
            vec!["/snap/a/tool".to_string(), "/snap/b/tool".to_string()],
            "both candidates list in a stable order: {exe:?}"
        );
    }

    /// Two system-index spellings for one pair: same rule — a shown
    /// path plus the ambiguity, never first-wins silence. The
    /// hardlinked pair shares its index bucket like snapshot clones
    /// share their inode.
    #[test]
    fn two_system_index_paths_for_one_pair_resolve_ambiguous() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("a-tool");
        std::fs::write(&first, b"tool").unwrap();
        let second = dir.path().join("b-tool");
        std::fs::hard_link(&first, &second).unwrap();
        let first_text = first.to_string_lossy().into_owned();
        let second_text = second.to_string_lossy().into_owned();
        let ino = std::fs::metadata(&first).unwrap().ino();
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(vec![dir.path().to_path_buf()]);
        resolver.set_scripted_maps_identities(HashMap::from([
            (first_text.clone(), (82, ino)),
            (second_text.clone(), (82, ino)),
        ]));
        let proc = ScriptedProc::dead();
        let scan = ScriptedScan::empty();
        let exe = resolver.resolve(
            7,
            82,
            ino,
            2_000_000_000,
            &proc.reads(true, Some(3_000_000_000), Some(3_000_000_000)),
            &scan.scan(),
        );
        assert_eq!(exe.resolution, ExeResolution::SystemIndex);
        assert!(
            exe.path.as_deref() == Some(first_text.as_str())
                || exe.path.as_deref() == Some(second_text.as_str()),
            "a colliding pair keeps a shown path: {exe:?}"
        );
        assert!(
            exe.identity_ambiguous(),
            "a colliding pair reads ambiguous: {exe:?}"
        );
        assert_eq!(
            exe.identity_candidates,
            vec![first_text, second_text],
            "both candidates list in a stable order: {exe:?}"
        );
    }

    /// A learned spelling beats an index spelling for the shown
    /// path (an admitted caller proved it executes) while both
    /// list as candidates, sorted.
    #[test]
    fn learned_spelling_is_preferred_over_an_index_spelling() {
        let dir = tempfile::tempdir().unwrap();
        let indexed = dir.path().join("tool");
        std::fs::write(&indexed, b"tool").unwrap();
        let indexed_text = indexed.to_string_lossy().into_owned();
        let ino = std::fs::metadata(&indexed).unwrap().ino();
        let learned = "/snap/learned/tool";
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(vec![dir.path().to_path_buf()]);
        resolver.set_scripted_maps_identities(HashMap::from([(indexed_text.clone(), (82, ino))]));
        let proc = ScriptedProc::dead();
        let mut scan = ScriptedScan::empty();
        scan.learned(82, ino, learned, Some((82, ino)));
        let exe = resolver.resolve(
            7,
            82,
            ino,
            2_000_000_000,
            &proc.reads(true, Some(3_000_000_000), Some(3_000_000_000)),
            &scan.scan(),
        );
        assert_eq!(exe.resolution, ExeResolution::ScanLearned);
        assert_eq!(exe.path.as_deref(), Some(learned));
        assert!(exe.identity_ambiguous(), "{exe:?}");
        let mut expected = vec![learned.to_string(), indexed_text];
        expected.sort();
        assert_eq!(exe.identity_candidates, expected, "{exe:?}");
    }

    /// Two spellings of one file (a symlinked parent dir, like a
    /// merged-`/usr` `/bin/x` vs `/usr/bin/x` pair) name one
    /// candidate — the sorted-first spelling — with no false
    /// ambiguity.
    #[test]
    fn canonical_aliases_of_one_file_read_unambiguous() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join("tool"), b"tool").unwrap();
        std::os::unix::fs::symlink(&real, dir.path().join("link")).unwrap();
        let direct = real.join("tool").to_string_lossy().into_owned();
        let aliased = dir.path().join("link/tool").to_string_lossy().into_owned();
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(Vec::new());
        let proc = ScriptedProc::dead();
        let mut scan = ScriptedScan::empty();
        scan.learned_multi(82, 257, &[&direct, &aliased]);
        let exe = resolver.resolve(
            7,
            82,
            257,
            2_000_000_000,
            &proc.reads(true, Some(3_000_000_000), Some(3_000_000_000)),
            &scan.scan(),
        );
        assert_eq!(exe.resolution, ExeResolution::ScanLearned);
        // Sorted-first spelling wins deterministically.
        assert_eq!(exe.path.as_deref(), Some(aliased.as_str()));
        assert!(!exe.identity_ambiguous(), "{exe:?}");
        assert_eq!(exe.identity_candidates, vec![aliased], "{exe:?}");
    }

    /// The primary spelling verifies once even when it also
    /// lists among the known teacher spellings.
    #[test]
    fn learned_primary_verifies_once() {
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(Vec::new());
        let proc = ScriptedProc::dead();
        let mut scan = ScriptedScan::empty();
        scan.learned_multi(8, 99, &["/usr/bin/x", "/alt/bin/x"]);
        let exe = resolver.resolve(
            7,
            8,
            99,
            2_000_000_000,
            &proc.reads(true, Some(3_000_000_000), Some(3_000_000_000)),
            &scan.scan(),
        );
        assert_eq!(exe.resolution, ExeResolution::ScanLearned);
        assert_eq!(scan.verify_calls.get(), 2);
    }

    /// (b): a learned path whose current maps-domain identity
    /// differs (the file was replaced) is refused.
    #[test]
    fn scan_learned_stale_path_refuses() {
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(Vec::new());
        let proc = ScriptedProc::dead();
        let mut scan = ScriptedScan::empty();
        scan.learned(8, 99, "/usr/bin/x", Some((8, 1000)));
        let exe = resolver.resolve(
            7,
            8,
            99,
            2_000_000_000,
            &proc.reads(true, Some(3_000_000_000), Some(3_000_000_000)),
            &scan.scan(),
        );
        assert_eq!(exe.resolution, ExeResolution::PathUnknown);
        assert_eq!(scan.verify_calls.get(), 1);
    }

    /// (c): the process is gone and the scan never saw the binary,
    /// but the system index holds the joined maps-domain identity.
    #[test]
    fn system_index_resolves_after_exit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tool");
        std::fs::write(&path, b"tool").unwrap();
        let path_text = path.to_string_lossy().into_owned();
        let (dev, ino) = real_maps_identity(&path_text).expect("the staged tool maps");
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(vec![dir.path().to_path_buf()]);
        let proc = ScriptedProc::dead();
        let scan = ScriptedScan::empty();
        let exe = resolver.resolve(
            7,
            dev,
            ino,
            2_000_000_000,
            &proc.reads(true, Some(3_000_000_000), Some(3_000_000_000)),
            &scan.scan(),
        );
        assert_eq!(
            exe,
            UnboundExe {
                dev,
                ino,
                path: Some(path.to_string_lossy().into_owned()),
                resolution: ExeResolution::SystemIndex,
                identity_candidates: vec![path.to_string_lossy().into_owned()],
            }
        );
        assert_eq!(
            resolver.index_builds(),
            1,
            "the first miss builds the index once"
        );
    }

    /// (c): only listed dirs are indexed — a binary elsewhere never
    /// resolves through the index.
    #[test]
    fn system_index_ignores_unlisted_dirs() {
        let listed = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let path = elsewhere.path().join("tool");
        std::fs::write(&path, b"tool").unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(vec![listed.path().to_path_buf()]);
        let proc = ScriptedProc::dead();
        let scan = ScriptedScan::empty();
        let exe = resolver.resolve(
            7,
            kdev_of(&meta),
            meta.ino(),
            2_000_000_000,
            &proc.reads(true, Some(3_000_000_000), Some(3_000_000_000)),
            &scan.scan(),
        );
        assert_eq!(exe.resolution, ExeResolution::PathUnknown);
    }

    /// (d): nothing names the joined pair.
    #[test]
    fn unknown_identity_reports_path_unknown() {
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(Vec::new());
        let proc = ScriptedProc::dead();
        let scan = ScriptedScan::empty();
        let exe = resolver.resolve(
            7,
            8,
            99,
            2_000_000_000,
            &proc.reads(true, Some(3_000_000_000), Some(3_000_000_000)),
            &scan.scan(),
        );
        assert_eq!(
            exe,
            UnboundExe {
                dev: 8,
                ino: 99,
                path: None,
                resolution: ExeResolution::PathUnknown,
                identity_candidates: Vec::new(),
            }
        );
    }

    /// A deleted binary: the index named it once, but the path no
    /// longer maps, so the lookup-time verification refuses.
    #[test]
    fn deleted_binary_stays_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tool");
        std::fs::write(&path, b"tool").unwrap();
        let path_text = path.to_string_lossy().into_owned();
        let (dev, ino) = real_maps_identity(&path_text).expect("the staged tool maps");
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(vec![dir.path().to_path_buf()]);
        let proc = ScriptedProc::dead();
        let scan = ScriptedScan::empty();
        let first = resolver.resolve(
            7,
            dev,
            ino,
            2_000_000_000,
            &proc.reads(true, Some(3_000_000_000), Some(3_000_000_000)),
            &scan.scan(),
        );
        assert_eq!(first.resolution, ExeResolution::SystemIndex);
        std::fs::remove_file(&path).unwrap();
        let second = resolver.resolve(
            7,
            dev,
            ino,
            2_000_000_000,
            &proc.reads(true, Some(3_000_000_000), Some(3_000_000_000)),
            &scan.scan(),
        );
        assert_eq!(second.resolution, ExeResolution::PathUnknown);
        assert_eq!((second.dev, second.ino), (dev, ino));
    }

    /// A `(0, 0)` pair means the kernel read failed: unavailable
    /// without any userspace read.
    #[test]
    fn zero_pair_is_unavailable_without_reads() {
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(Vec::new());
        let proc = ScriptedProc::live(100, 8, 99, "/bin/x");
        let mut scan = ScriptedScan::empty();
        scan.learned(8, 99, "/usr/bin/x", Some((8, 99)));
        let exe = resolver.resolve(
            7,
            0,
            0,
            2_000_000_000,
            &proc.reads(true, Some(3_000_000_000), Some(3_000_000_000)),
            &scan.scan(),
        );
        assert_eq!(
            exe,
            UnboundExe {
                dev: 0,
                ino: 0,
                path: None,
                resolution: ExeResolution::ExeUnavailable,
                identity_candidates: Vec::new(),
            }
        );
        assert_eq!(proc.start_calls.get() + proc.exe_calls.get(), 0);
        assert_eq!(scan.verify_calls.get(), 0);
        assert_eq!(resolver.index_builds(), 0, "no pair means no index build");
    }

    /// The index is built once on the first miss and cached.
    #[test]
    fn index_is_built_once_and_cached() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tool");
        std::fs::write(&path, b"tool").unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(vec![dir.path().to_path_buf()]);
        let proc = ScriptedProc::dead();
        let scan = ScriptedScan::empty();
        let reads = || proc.reads(true, Some(9_000_000_000), Some(9_000_000_000));
        resolver.resolve(
            7,
            kdev_of(&meta),
            meta.ino(),
            2_000_000_000,
            &reads(),
            &scan.scan(),
        );
        resolver.resolve(
            8,
            kdev_of(&meta),
            meta.ino(),
            2_000_000_000,
            &reads(),
            &scan.scan(),
        );
        assert_eq!(resolver.index_builds(), 1);
        assert_eq!(resolver.index_len(), 1);
    }

    /// The index is bounded: past the cap, entries shed and the
    /// length never exceeds it.
    #[test]
    fn index_is_bounded() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["a", "b", "c", "d", "e"] {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(vec![dir.path().to_path_buf()]);
        resolver.set_index_cap(3);
        let proc = ScriptedProc::dead();
        let scan = ScriptedScan::empty();
        resolver.resolve(
            7,
            8,
            99,
            2_000_000_000,
            &proc.reads(true, Some(3_000_000_000), Some(3_000_000_000)),
            &scan.scan(),
        );
        assert_eq!(resolver.index_len(), 3);
        assert_eq!(resolver.index_shed(), 2);
    }

    /// A final-component symlink is never indexed: the
    /// confirmation probe would refuse it, so it must not spend cap.
    #[test]
    fn index_skips_final_component_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("tool");
        std::fs::write(&target, b"tool").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("link")).unwrap();
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(vec![dir.path().to_path_buf()]);
        let proc = ScriptedProc::dead();
        let scan = ScriptedScan::empty();
        resolver.resolve(
            7,
            8,
            99,
            2_000_000_000,
            &proc.reads(true, Some(3_000_000_000), Some(3_000_000_000)),
            &scan.scan(),
        );
        assert_eq!(resolver.index_len(), 1);
    }

    /// LIM-1: the index cap is pinned from measurement (5,675
    /// entries walked on the build host) and is never lowered.
    #[test]
    fn index_cap_pinned_from_measurement() {
        assert_eq!(DEFAULT_MAX_SYSTEM_INDEX_ENTRIES, 65_536);
    }

    /// The index refreshes at most every few seconds.
    #[test]
    fn index_refresh_is_gated_by_time() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a"), b"x").unwrap();
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(vec![dir.path().to_path_buf()]);
        resolver.set_now(1_000_000_000);
        let proc = ScriptedProc::dead();
        let scan = ScriptedScan::empty();
        let reads = || proc.reads(true, Some(9_000_000_000), Some(9_000_000_000));
        resolver.resolve(7, 8, 99, 2_000_000_000, &reads(), &scan.scan());
        assert_eq!(resolver.index_builds(), 1);
        resolver.set_now(1_000_000_000 + 1_000_000_000);
        resolver.resolve(7, 8, 99, 2_000_000_000, &reads(), &scan.scan());
        assert_eq!(resolver.index_builds(), 1, "no rebuild within the window");
        std::fs::write(dir.path().join("b"), b"x").unwrap();
        resolver.set_now(1_000_000_000 + 60_000_000_000);
        resolver.resolve(7, 8, 99, 2_000_000_000, &reads(), &scan.scan());
        assert_eq!(resolver.index_builds(), 2, "a stale index rebuilds");
        assert_eq!(resolver.index_len(), 2);
    }

    /// (c) on a btrfs-style host: the EXEC's mapped device differs
    /// from the path's stat device, but the mapped identity matches,
    /// so the index still resolves. The scripted maps answer stands
    /// in for the split-device host.
    #[test]
    fn system_index_bridges_split_stat_and_maps_devices() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tool");
        std::fs::write(&path, b"tool").unwrap();
        let path_text = path.to_string_lossy().into_owned();
        let meta = std::fs::metadata(&path).unwrap();
        let mapped_dev = meta.dev().wrapping_add(0x1_0000_0000);
        assert_ne!(
            mapped_dev,
            meta.dev(),
            "the test needs split stat/maps devices"
        );
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(vec![dir.path().to_path_buf()]);
        resolver.set_scripted_maps_identities(HashMap::from([(
            path_text.clone(),
            (mapped_dev, meta.ino()),
        )]));
        let proc = ScriptedProc::dead();
        let scan = ScriptedScan::empty();
        let exe = resolver.resolve(
            7,
            mapped_dev,
            meta.ino(),
            2_000_000_000,
            &proc.reads(true, Some(3_000_000_000), Some(3_000_000_000)),
            &scan.scan(),
        );
        assert_eq!(
            exe,
            UnboundExe {
                dev: mapped_dev,
                ino: meta.ino(),
                path: Some(path_text.clone()),
                resolution: ExeResolution::SystemIndex,
                identity_candidates: vec![path_text],
            }
        );
    }

    /// (c): a stat-domain pair that never mapped to the indexed path
    /// (the btrfs split read backwards) stays unknown: stat alone
    /// never confirms an EXEC pair.
    #[test]
    fn system_index_refuses_stat_only_pairs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tool");
        std::fs::write(&path, b"tool").unwrap();
        let path_text = path.to_string_lossy().into_owned();
        let meta = std::fs::metadata(&path).unwrap();
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(vec![dir.path().to_path_buf()]);
        resolver.set_scripted_maps_identities(HashMap::from([(
            path_text,
            (meta.dev().wrapping_add(1), meta.ino()),
        )]));
        let proc = ScriptedProc::dead();
        let scan = ScriptedScan::empty();
        let exe = resolver.resolve(
            7,
            meta.dev(),
            meta.ino(),
            2_000_000_000,
            &proc.reads(true, Some(3_000_000_000), Some(3_000_000_000)),
            &scan.scan(),
        );
        assert_eq!(exe.resolution, ExeResolution::PathUnknown);
        assert_eq!((exe.dev, exe.ino, exe.path), (meta.dev(), meta.ino(), None));
    }

    /// The mapping probe names the file's own maps identity: the ino
    /// always matches stat (inos are not device-domain values), and
    /// the pair is stable across calls.
    #[test]
    fn maps_probe_names_the_file_it_maps() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tool");
        std::fs::write(&path, b"tool").unwrap();
        let path_text = path.to_string_lossy().into_owned();
        let meta = std::fs::metadata(&path).unwrap();
        let first = real_maps_identity(&path_text).expect("the staged tool maps");
        assert_eq!(first.1, meta.ino(), "the mapped ino is the file's ino");
        let second = real_maps_identity(&path_text).expect("the probe is repeatable");
        assert_eq!(first, second, "the mapped identity is stable");
    }

    /// The mapping probe fails closed: missing, empty, and
    /// non-file paths read `None`, never a guessed pair.
    #[test]
    fn maps_probe_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            real_maps_identity(dir.path().join("absent").to_str().unwrap()),
            None
        );
        let empty = dir.path().join("empty");
        std::fs::write(&empty, b"").unwrap();
        assert_eq!(
            real_maps_identity(empty.to_str().unwrap()),
            None,
            "an empty file has no page to map"
        );
        assert_eq!(
            real_maps_identity(dir.path().to_str().unwrap()),
            None,
            "a directory is not mappable"
        );
    }

    /// The maps parser finds the covering mapping (wide major/minor
    /// included) and skips malformed lines without failing the read.
    #[test]
    fn maps_parser_finds_the_covering_mapping() {
        let maps = "\
00400000-00401000 r--p 00000000 103:04 99 /bin/x
malformed line without fields
7f00-7g00 r--p 00000000 00:00 0
7fab0000-7fab1000 r--p 00000000 00:2f 4242 /lib/y
";
        let expect = Device {
            major: 0x103,
            minor: 0x04,
        }
        .to_kdev();
        assert_eq!(maps_identity_at(maps, 0x0040_0000), Some((expect, 99)));
        assert_eq!(maps_identity_at(maps, 0x0040_0fff), Some((expect, 99)));
        assert_eq!(maps_identity_at(maps, 0x0040_1000), None);
        assert_eq!(
            maps_identity_at(maps, 0x7fab_0000).map(|pair| pair.1),
            Some(4242)
        );
        assert_eq!(maps_identity_at("", 0x0040_0000), None);
    }

    /// Device-mapper twin: the maps `fd:01` pair decodes to the raw
    /// kernel `s_dev` word, not the userspace `makedev` layout.
    #[test]
    fn maps_parser_decodes_dm_device_like_the_kernel() {
        let maps = "00400000-00401000 r--p 00000000 fd:01 99 /bin/x\n";
        assert_eq!(
            maps_identity_at(maps, 0x0040_0000),
            Some(((0xfdu64 << 20) | 1, 99))
        );
    }

    /// Overlay twin: a big minor (`00:14d`) decodes to the raw kernel
    /// `s_dev` word, not the userspace `makedev` layout.
    #[test]
    fn maps_parser_decodes_big_overlay_minor_like_the_kernel() {
        let maps = "00400000-00401000 r--p 00000000 00:14d 99 /bin/x\n";
        assert_eq!(maps_identity_at(maps, 0x0040_0000), Some((0x14d, 99)));
    }

    /// The probe never follows a final-component symlink: a link to a
    /// regular file is refused, so a link swapped in under a
    /// user-writable dir can never redirect the probe at another file.
    #[test]
    fn maps_probe_refuses_symlinks_without_following() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("tool");
        std::fs::write(&target, b"tool").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(real_maps_identity(link.to_str().unwrap()), None);
    }

    /// The probe never opens the device behind a symlink: a link to
    /// `/dev/zero` fails closed without touching the device.
    #[test]
    fn maps_probe_refuses_a_symlink_to_a_device() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("device");
        std::os::unix::fs::symlink("/dev/zero", &link).unwrap();
        assert_eq!(real_maps_identity(link.to_str().unwrap()), None);
    }

    /// The probe never blocks on a FIFO: a writerless FIFO fails
    /// closed instead of hanging the root observer forever.
    #[test]
    fn maps_probe_never_blocks_on_a_fifo() {
        use std::os::unix::ffi::OsStrExt as _;
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("fifo");
        let raw = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: a fresh private path, mode 0600.
        assert_eq!(
            unsafe { libc::mkfifo(raw.as_ptr(), 0o600) },
            0,
            "the fifo stages"
        );
        let path = fifo.to_str().unwrap().to_string();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done_tx.send(real_maps_identity(&path));
        });
        let answer = done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the probe must not block on a fifo");
        assert_eq!(answer, None);
    }

    /// Source (a): opening `/proc/<pid>/exe` itself names the same
    /// identity as probing the resolved target.
    #[test]
    fn proc_exe_link_agrees_with_the_resolved_target() {
        let pid = std::process::id();
        let proc_exe = format!("/proc/{pid}/exe");
        let link = std::fs::read_link(&proc_exe).unwrap();
        let link_text = link.to_string_lossy().into_owned();
        let via_link = real_maps_identity_proc_exe_link(&proc_exe).expect("our own exe opens");
        let via_target = real_maps_identity(&link_text).expect("our own exe maps");
        assert_eq!(via_link, via_target);
    }

    /// Source (a): only `/proc/<digits>/exe` resolves here — every
    /// other shape, however mappable, is refused.
    #[test]
    fn proc_exe_link_refuses_non_proc_paths() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tool");
        std::fs::write(&path, b"tool").unwrap();
        let path_text = path.to_string_lossy().into_owned();
        assert!(
            real_maps_identity(&path_text).is_some(),
            "the staged tool maps"
        );
        assert_eq!(real_maps_identity_proc_exe_link(&path_text), None);
        assert_eq!(real_maps_identity_proc_exe_link("/proc/self/exe"), None);
        assert_eq!(real_maps_identity_proc_exe_link("/proc//exe"), None);
    }

    /// Create one btrfs subvolume under `parent` through the raw
    /// ioctl (no `btrfs` CLI at runtime), like the D4 cells.
    fn create_btrfs_subvolume(parent: &Path, name: &str) {
        use std::os::fd::AsRawFd as _;
        #[repr(C)]
        struct VolArgs {
            fd: i64,
            name: [u8; 4088],
        }
        // musl `ioctl` takes a c_int request, glibc a c_ulong one; the
        // number fits both.
        #[cfg(target_env = "musl")]
        const BTRFS_IOC_SUBVOL_CREATE: libc::c_int = 0x5000_940e;
        #[cfg(not(target_env = "musl"))]
        const BTRFS_IOC_SUBVOL_CREATE: libc::c_ulong = 0x5000_940e;
        let dir = std::fs::File::open(parent).unwrap();
        let mut args = VolArgs {
            fd: 0,
            name: [0; 4088],
        };
        args.name[..name.len()].copy_from_slice(name.as_bytes());
        // SAFETY: a valid directory fd and a NUL-terminated name in a
        // correctly sized btrfs_ioctl_vol_args.
        let rc = unsafe { libc::ioctl(dir.as_raw_fd(), BTRFS_IOC_SUBVOL_CREATE, &args) };
        assert_eq!(rc, 0, "{}", std::io::Error::last_os_error());
    }

    /// Live subvolume twins on btrfs: the same payload written to two
    /// fresh subvolumes shares the kernel `(s_dev, ino)` pair while
    /// stat reports two subvolume devices (the file-identity audit
    /// shape). Two teacher spellings for that pair resolve to a
    /// shown path that stays marked ambiguous with both candidates.
    /// Root lane with TMPDIR on btrfs (the runner provisions a loop
    /// mount for the group); the fixture subvolumes live and die on
    /// that disposable mount.
    #[test]
    #[ignore = "privileged: btrfs subvolume twins resolve ambiguous (root, btrfs TMPDIR)"]
    fn privileged_btrfs_subvolume_collision_resolves_ambiguous() {
        // SAFETY: reading the effective uid has no preconditions.
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "run as root in the btrfs campaign lane"
        );
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path();
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
        let c_parent = std::ffi::CString::new(parent.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid path and writable statfs buffer, read only on success.
        assert_eq!(
            unsafe { libc::statfs(c_parent.as_ptr(), stat.as_mut_ptr()) },
            0
        );
        // SAFETY: initialized by the successful statfs above.
        // `f_type` is signed on glibc and unsigned on musl; the magic fits both.
        #[allow(clippy::unnecessary_cast)]
        let magic = unsafe { stat.assume_init().f_type } as u64 & 0xffff_ffff;
        assert_eq!(magic, 0x9123_683e, "actual fixture TMPDIR must be Btrfs");
        create_btrfs_subvolume(parent, "a");
        create_btrfs_subvolume(parent, "b");
        let a_path = parent.join("a/tool");
        let b_path = parent.join("b/tool");
        std::fs::write(&a_path, vec![0x7fu8; 4096]).unwrap();
        std::fs::write(&b_path, vec![0x7fu8; 4096]).unwrap();
        let a_text = a_path.to_string_lossy().into_owned();
        let b_text = b_path.to_string_lossy().into_owned();
        let pair_a = real_maps_identity(&a_text).expect("twin A maps");
        let pair_b = real_maps_identity(&b_text).expect("twin B maps");
        assert_eq!(pair_a, pair_b, "subvolume twins share the kernel pair");
        let meta_a = std::fs::metadata(&a_path).unwrap();
        let meta_b = std::fs::metadata(&b_path).unwrap();
        assert_eq!(meta_a.ino(), meta_b.ino(), "twins share the inode number");
        assert_ne!(
            meta_a.dev(),
            meta_b.dev(),
            "twins live on two subvolume devices"
        );
        let mut by_identity = HashMap::new();
        by_identity.insert(pair_a, a_text.clone());
        let mut all = HashMap::new();
        all.insert(pair_a, vec![a_text.clone(), b_text.clone()]);
        let scan = ScanLearned {
            by_identity: &by_identity,
            verify: Box::new(real_maps_identity),
            all_by_identity: Some(&all),
        };
        let mut resolver = ExeResolver::new();
        resolver.set_index_dirs(Vec::new());
        let proc = ScriptedProc::dead();
        let exe = resolver.resolve(
            7,
            pair_a.0,
            pair_a.1,
            2_000_000_000,
            &proc.reads(true, Some(3_000_000_000), Some(3_000_000_000)),
            &scan,
        );
        assert_eq!(exe.resolution, ExeResolution::ScanLearned);
        assert!(
            exe.path.as_deref() == Some(a_text.as_str())
                || exe.path.as_deref() == Some(b_text.as_str()),
            "the collision keeps a shown path: {exe:?}"
        );
        assert!(
            exe.identity_ambiguous(),
            "the collision reads ambiguous: {exe:?}"
        );
        let mut candidates = exe.identity_candidates.clone();
        candidates.sort();
        assert_eq!(candidates, vec![a_text, b_text], "both twins list: {exe:?}");
    }

    /// The user question "which program called?" over one short-lived
    /// run: `inventory --system --capture native` while `pkcs11-tool
    /// --module <private SoftHSM> -O` runs once must NAME the tool in
    /// `modules[].unbound_use.executables` (its EXEC-joined pair
    /// resolved to the exact tool path with a resolved verdict) and on
    /// the concise `unidentified executables` line — not just its pid.
    /// The oracle matches the tool's own mapped-domain pair, so a
    /// pid-only or path-unknown record fails; attempts where the run
    /// binds to a caller edge (or its calls are missed) retry with a
    /// fresh capture, since only an unidentified image exercises the
    /// EXEC join. A holder keeps the SoftHSM module mapped for the
    /// whole cell: discovery attaches mapped modules, and the
    /// short-lived tool alone maps it too briefly. Root BPF lane, run
    /// serially through `scripts/run-privileged-lib-tests.sh`; the
    /// fixed test PIN travels only in this cell's own argv, which the
    /// observer never reads.
    #[test]
    #[ignore = "privileged: one pkcs11-tool run under inventory --system names its executable (root, BPF, SoftHSM, pkcs11-tool)"]
    fn privileged_shortlived_tool_run_names_its_executable() {
        // SAFETY: reading the effective uid has no preconditions.
        assert_eq!(
            unsafe { libc::geteuid() },
            0,
            "run as root via scripts/run-privileged-lib-tests.sh"
        );
        const TOOL_CANDIDATES: &[&str] = &["/usr/bin/pkcs11-tool", "/usr/local/bin/pkcs11-tool"];
        let tool = TOOL_CANDIDATES
            .iter()
            .copied()
            .find(|path| std::path::Path::new(path).is_file())
            .expect("a pkcs11-tool binary must be installed for the cell");
        const SOFTHSM_CANDIDATES: &[&str] = &[
            "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
            "/usr/lib/softhsm/libsofthsm2.so",
            "/usr/lib64/pkcs11/libsofthsm2.so",
        ];
        let module = SOFTHSM_CANDIDATES
            .iter()
            .copied()
            .find(|path| std::path::Path::new(path).is_file())
            .expect("a SoftHSM2 provider must be installed for the cell");
        let (kdev, ino) = real_maps_identity(tool).expect("the tool maps");
        let device = Device::from_kdev(kdev);
        let dir = tempfile::tempdir().expect("cell dir");
        let tokens = dir.path().join("tokens");
        std::fs::create_dir_all(&tokens).expect("token dir");
        let conf = dir.path().join("softhsm2.conf");
        std::fs::write(
            &conf,
            format!(
                "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
                tokens.display()
            ),
        )
        .expect("token conf");
        let output = std::process::Command::new("/usr/bin/softhsm2-util")
            .env("SOFTHSM2_CONF", &conf)
            .args([
                "--init-token",
                "--free",
                "--label",
                "exename",
                "--so-pin",
                "5678",
                "--pin",
                "1234",
            ])
            .output()
            .expect("spawn softhsm2-util");
        assert!(
            output.status.success(),
            "token init: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let _holder = MappedHolder::spawn(module, &conf);
        let observer = exename_observer_binary();
        let mut last = String::from("no attempt ran");
        for attempt in 1..=3 {
            let out = dir.path().join(format!("attempt{attempt}.json"));
            let log = dir.path().join(format!("attempt{attempt}.log"));
            let err = dir.path().join(format!("attempt{attempt}.err"));
            let log_file = std::fs::File::create(&log).expect("attempt log");
            let err_file = std::fs::File::create(&err).expect("attempt err");
            let mut child = std::process::Command::new(&observer)
                .env("SOFTHSM2_CONF", &conf)
                .args([
                    "inventory",
                    "--system",
                    "--capture",
                    "native",
                    "--module",
                    module,
                    "--duration",
                    "60",
                    "-o",
                ])
                .arg(&out)
                .stdin(std::process::Stdio::null())
                .stdout(log_file)
                .stderr(err_file)
                .spawn()
                .expect("spawn the observer");
            std::thread::sleep(std::time::Duration::from_secs(20));
            if let Some(status) = child.try_wait().expect("poll the observer") {
                let stderr = std::fs::read_to_string(&err).unwrap_or_default();
                panic!("the observer exited {status} before the workload: {stderr}");
            }
            let run = std::process::Command::new(tool)
                .env("SOFTHSM2_CONF", &conf)
                .args(["--module", module, "-O", "--login", "--pin", "1234"])
                .output()
                .expect("spawn pkcs11-tool");
            assert!(
                run.status.success(),
                "pkcs11-tool: {}",
                String::from_utf8_lossy(&run.stderr)
            );
            let status = exename_wait(&mut child, 180).expect("the observer exits");
            assert_eq!(status.code(), Some(0), "inventory exits 0");
            let document: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&out).expect("report exists"))
                    .expect("the report parses");
            match exename_oracle(&document, tool, device, ino) {
                ExenameVerdict::Pass => {
                    let text = std::fs::read_to_string(&log).expect("attempt log");
                    let line = text
                        .split("unidentified executables:")
                        .nth(1)
                        .and_then(|tail| tail.lines().next())
                        .unwrap_or_default();
                    assert!(
                        line.contains("pkcs11-tool"),
                        "the concise line names the tool: {line}"
                    );
                    return;
                }
                ExenameVerdict::Retry(detail) => last = detail,
                ExenameVerdict::Fail(detail) => {
                    panic!("attempt {attempt}: our pair is unnamed: {detail}")
                }
            }
        }
        panic!("no passing attempt ({last})");
    }

    /// A child reaped on every exit path: the runner kills the cell on
    /// timeout, and Drop still reaps a live child on panic paths.
    struct ExenameChild(std::process::Child);

    impl Drop for ExenameChild {
        fn drop(&mut self) {
            if self.0.try_wait().is_ok_and(|waiting| waiting.is_none()) {
                let _ = self.0.kill();
            }
            let _ = self.0.wait();
        }
    }

    /// The SoftHSM holder: a python process with the provider dlopened,
    /// kept mapped until the cell ends so discovery attaches the module.
    struct MappedHolder {
        _child: ExenameChild,
    }

    impl MappedHolder {
        fn spawn(module: &str, conf: &std::path::Path) -> Self {
            let child = std::process::Command::new("/usr/bin/python3")
                .env("SOFTHSM2_CONF", conf)
                .args([
                    "-I",
                    "-c",
                    "import ctypes, sys, time; ctypes.CDLL(sys.argv[1]); time.sleep(600)",
                    module,
                ])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("spawn the SoftHSM holder");
            let pid = child.id();
            let mut holder = Self {
                _child: ExenameChild(child),
            };
            for _ in 0..100 {
                if holder
                    ._child
                    .0
                    .try_wait()
                    .expect("poll the holder")
                    .is_some()
                {
                    panic!("the holder exited before mapping the provider");
                }
                let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).unwrap_or_default();
                if maps.contains("libsofthsm2.so") {
                    return holder;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            panic!("the holder never mapped libsofthsm2.so");
        }
    }

    /// The observer under test: an explicit `P11SCOPE_E2E_OBSERVER`
    /// binary or the `p11scope` sibling of this test binary's directory
    /// (a local `cargo build` layout).
    fn exename_observer_binary() -> std::path::PathBuf {
        if let Ok(path) = std::env::var("P11SCOPE_E2E_OBSERVER") {
            let path = std::path::PathBuf::from(path);
            assert!(path.exists(), "P11SCOPE_E2E_OBSERVER is missing");
            return path;
        }
        let sibling = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent()?.parent().map(|dir| dir.join("p11scope")));
        if let Some(sibling) = sibling.filter(|path| path.exists()) {
            return sibling;
        }
        panic!(
            "no observer binary: set P11SCOPE_E2E_OBSERVER or build the p11scope binary beside this test binary"
        );
    }

    /// Bounded wait: poll the observer, then kill it instead of hanging
    /// the campaign lane forever.
    fn exename_wait(
        child: &mut std::process::Child,
        seconds: u64,
    ) -> Option<std::process::ExitStatus> {
        for _ in 0..seconds * 10 {
            if let Some(status) = child.try_wait().expect("poll the observer") {
                return Some(status);
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
        None
    }

    enum ExenameVerdict {
        Pass,
        Retry(String),
        Fail(String),
    }

    /// The cell oracle: PASS names our pair at the exact tool path with
    /// a resolved verdict, RETRY missed it (bound to a caller edge or
    /// its calls were missed), FAIL leaves it unnamed or misnamed.
    fn exename_oracle(
        document: &serde_json::Value,
        tool: &str,
        device: Device,
        ino: u64,
    ) -> ExenameVerdict {
        let Some(modules) = document.get("modules").and_then(|m| m.as_array()) else {
            return ExenameVerdict::Fail("document has no modules[]".to_string());
        };
        let mut seen = Vec::new();
        for module in modules {
            let executables = module
                .get("unbound_use")
                .and_then(|use_| use_.get("executables"));
            let Some(executables) = executables else {
                continue;
            };
            let Some(executables) = executables.as_array() else {
                return ExenameVerdict::Fail("executables is not a list".to_string());
            };
            for record in executables {
                let pair = record.get("dev").and_then(|dev| {
                    Some((
                        dev.get("major")?.as_u64()?,
                        dev.get("minor")?.as_u64()?,
                        record.get("ino")?.as_u64()?,
                    ))
                });
                let Some(pair) = pair else {
                    return ExenameVerdict::Fail(format!(
                        "executables[] record lacks dev{{ major, minor }}/ino: {record}"
                    ));
                };
                if pair == (device.major, device.minor, ino) {
                    seen.push(record);
                }
            }
        }
        if seen.is_empty() {
            return ExenameVerdict::Retry(
                "our (dev, ino) left no unidentified image (bound or missed)".to_string(),
            );
        }
        let unnamed: Vec<_> = seen
            .iter()
            .filter(|record| {
                record
                    .get("exe")
                    .and_then(|exe| exe.as_str())
                    .is_none_or(|exe| exe.is_empty())
                    || !matches!(
                        record.get("resolution").and_then(|r| r.as_str()),
                        Some("proc_alive" | "scan_learned" | "system_index")
                    )
            })
            .collect();
        if !unnamed.is_empty() {
            return ExenameVerdict::Fail(format!("our pair is unnamed: {unnamed:?}"));
        }
        let mut names: Vec<_> = seen
            .iter()
            .filter_map(|record| record.get("exe").and_then(|exe| exe.as_str()))
            .collect();
        names.sort_unstable();
        names.dedup();
        if names != [tool] {
            return ExenameVerdict::Fail(format!("our pair named the wrong path: {names:?}"));
        }
        ExenameVerdict::Pass
    }
}
