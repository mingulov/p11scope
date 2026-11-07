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
//! its reason. Every candidate is verified by matching `(dev, ino)`
//! with stat. No argv, environ, key, PIN, or payload is ever read.

use crate::discovery::caller_registry::{ExeIdentity, ExeResolution, UnboundExe};
use std::collections::HashMap;
use std::path::PathBuf;

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

/// Scan-learned identities for source (b): `(dev, ino)` to path,
/// re-verified by stat at use.
pub(crate) struct ScanLearned<'a> {
    pub by_identity: &'a HashMap<(u64, u64), String>,
    pub stat: Box<dyn Fn(&str) -> Option<(u64, u64)> + 'a>,
}

/// Lazy system-binary index plus resolution. RED stub: every input
/// reads a sentinel.
pub(crate) struct ExeResolver {
    #[cfg(test)]
    index_dirs: Option<Vec<PathBuf>>,
}

impl ExeResolver {
    pub(crate) fn new() -> Self {
        Self {
            #[cfg(test)]
            index_dirs: None,
        }
    }

    /// Resolve one EXEC-joined `(dev, ino)` pair to a path. RED stub.
    pub(crate) fn resolve(
        &mut self,
        pid: u32,
        dev: u64,
        ino: u64,
        hook_ts_ns: u64,
        proc: &ProcReads<'_>,
        scan: &ScanLearned<'_>,
    ) -> UnboundExe {
        let _ = (pid, dev, ino, hook_ts_ns, proc, scan);
        let _ = self.index_dirs();
        UnboundExe {
            dev: u64::MAX,
            ino: u64::MAX,
            path: None,
            resolution: ExeResolution::NoExecRecord,
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

    /// Test-only index entry cap. RED stub.
    #[cfg(test)]
    pub(crate) fn set_index_cap(&mut self, cap: usize) {
        let _ = cap;
    }

    /// Test-only clock override (nanoseconds, monotonic). RED stub.
    #[cfg(test)]
    pub(crate) fn set_now(&mut self, now_ns: u64) {
        let _ = now_ns;
    }

    /// Index builds so far. RED stub.
    #[cfg(test)]
    pub(crate) fn index_builds(&self) -> u64 {
        0
    }

    /// Indexed entries. RED stub.
    #[cfg(test)]
    pub(crate) fn index_len(&self) -> usize {
        0
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
    use std::os::unix::fs::MetadataExt as _;

    const TICK_NS: u64 = 10_000_000;

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
        stat_answers: HashMap<String, (u64, u64)>,
        stat_calls: Cell<usize>,
    }

    impl ScriptedScan {
        fn empty() -> Self {
            Self {
                map: HashMap::new(),
                stat_answers: HashMap::new(),
                stat_calls: Cell::new(0),
            }
        }

        fn learned(&mut self, dev: u64, ino: u64, path: &str, stat: Option<(u64, u64)>) {
            self.map.insert((dev, ino), path.to_string());
            if let Some(pair) = stat {
                self.stat_answers.insert(path.to_string(), pair);
            }
        }

        fn scan(&self) -> ScanLearned<'_> {
            ScanLearned {
                by_identity: &self.map,
                stat: Box::new(|path| {
                    self.stat_calls.set(self.stat_calls.get() + 1);
                    self.stat_answers.get(path).copied()
                }),
            }
        }
    }

    /// (a): a live process whose start predates the EXEC and whose
    /// exe stats to the joined pair resolves by its live link.
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
    /// `(dev, ino)` from an admitted caller.
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
            }
        );
    }

    /// (b): a learned path whose current stat differs (the file was
    /// replaced) is refused.
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
        assert_eq!(scan.stat_calls.get(), 1);
    }

    /// (c): the process is gone and the scan never saw the binary,
    /// but the system index holds the joined identity.
    #[test]
    fn system_index_resolves_after_exit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tool");
        std::fs::write(&path, b"tool").unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        let (dev, ino) = (meta.dev(), meta.ino());
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
            meta.dev(),
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
            }
        );
    }

    /// A deleted binary: the index named it once, but the path no
    /// longer stats, so the lookup-time verification refuses.
    #[test]
    fn deleted_binary_stays_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tool");
        std::fs::write(&path, b"tool").unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        let (dev, ino) = (meta.dev(), meta.ino());
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
            }
        );
        assert_eq!(proc.start_calls.get() + proc.exe_calls.get(), 0);
        assert_eq!(scan.stat_calls.get(), 0);
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
            meta.dev(),
            meta.ino(),
            2_000_000_000,
            &reads(),
            &scan.scan(),
        );
        resolver.resolve(
            8,
            meta.dev(),
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
}
