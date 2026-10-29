//! SPDX-License-Identifier: GPL-3.0-or-later
//! Extensive-mode executable dependency hints (6.14 Option B, D-transitive).
//!
//! A process that exits before its first caller binding leaves a
//! `pid_descendant_gaps` gap with no caller record. In extensive mode
//! (`--track-short-lived`, default OFF) the kernel records the exec-time
//! executable identity (`exe_file` device + inode) in the EXEC record, and
//! this module turns a gap hit into a bounded static-linkage hint:
//! does the dead process's executable (transitively, depth 2) name a
//! pinned watched provider, or the one PKCS#11 loader SONAME?
//!
//! Contract: `docs/privacy/allowlist-v3.md` (extensive-mode executable
//! dependency hints, Rows A–D, ratified D-transitive). A hint is never a
//! call, never a verdict, and never merged into observed-call or
//! caller-attribution shares. Over-budget or unverifiable analyses are
//! `unknown`, never partial-as-complete. Exit records are not receipts
//! (R57): nothing here settles birth, admission, absence, or calls.

use p11scope_ebpf_common::DiscoveryRecord;
use p11scope_manifest::maps::{Device, ObjectKey};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Row D (D-transitive): the executable is depth 0, its `DT_NEEDED`
/// entries are tested and resolved at depth 1, their entries at depth 2.
/// Depth-2 entries are tested but never descended into.
pub(crate) const HINT_MAX_DEPTH: u32 = 2;
/// Row D: at most 32 ELF objects opened and parsed per analysis.
pub(crate) const HINT_MAX_OBJECTS_PER_ANALYSIS: usize = 32;
/// Row D: at most 128 examined `DT_NEEDED` edges per analysis.
pub(crate) const HINT_MAX_EDGES_PER_ANALYSIS: usize = 128;
/// Row D: at most 1 MiB of ELF spans examined per executable analysis,
/// charging every span read including duplicates and failed parses.
pub(crate) const HINT_MAX_BYTES_PER_ANALYSIS: u64 = 1024 * 1024;
/// Row D: at most 64 MiB of ELF spans examined per capture.
pub(crate) const HINT_MAX_BYTES_PER_CAPTURE: u64 = 64 * 1024 * 1024;
/// Row D: at most 1,024 retained verdict-cache entries per capture.
pub(crate) const HINT_MAX_VERDICT_CACHE_ENTRIES: usize = 1024;
/// Row D: a needed-name string longer than 255 bytes voids the analysis.
pub(crate) const HINT_MAX_NEEDED_NAME_BYTES: usize = 255;
/// Implementation ceiling (narrowing): the scan-learned path cache keeps
/// at most 4,096 entries and stops retaining when full.
pub(crate) const HINT_MAX_PATH_CACHE_ENTRIES: usize = 4096;
/// Implementation ceiling (narrowing): pending exe identities, one per
/// PID, bounded like the unmatched-exit ledger they feed.
pub(crate) const HINT_MAX_EXE_STASH_ENTRIES: usize = 256;
/// Row C: the loader vocabulary is exactly this one SONAME.
pub(crate) const HINT_LOADER_SONAME: &[u8] = b"libp11-kit.so.0";
/// Row C: every hint publication carries this label plus its scope.
pub(crate) const STATIC_HINT_LABEL: &str = "STATIC HINT";
/// Row C/D: the scope string published beside every hint split.
pub(crate) const STATIC_HINT_SCOPE_D_TRANSITIVE: &str = "D-transitive depth=2 objects<=32 edges<=128 exe-bytes<=1MiB capture-bytes<=64MiB names<=255B verdicts<=1024";

/// Row C: the finite per-gap hint classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StaticHint {
    LinksProvider,
    LinksPkcs11Loader,
    NoStaticLinkWithinScope,
    Unknown,
}

impl StaticHint {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::LinksProvider => "links_provider",
            Self::LinksPkcs11Loader => "links_pkcs11_loader",
            Self::NoStaticLinkWithinScope => "no_static_link_within_scope",
            Self::Unknown => "unknown",
        }
    }
}

/// Row C: per-gap classification counts. The four counts sum to the
/// analyzed unmatched-exit subpopulation, never to `pid_descendant_gaps`
/// itself (admissions and overflow sentinels carry no hint).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct GapExeHints {
    pub links_provider: u64,
    pub links_pkcs11_loader: u64,
    pub no_static_link_within_scope: u64,
    pub unknown: u64,
}

impl GapExeHints {
    pub(crate) fn total(self) -> u64 {
        self.links_provider
            .saturating_add(self.links_pkcs11_loader)
            .saturating_add(self.no_static_link_within_scope)
            .saturating_add(self.unknown)
    }

    fn count(&mut self, hint: StaticHint) {
        let cell = match hint {
            StaticHint::LinksProvider => &mut self.links_provider,
            StaticHint::LinksPkcs11Loader => &mut self.links_pkcs11_loader,
            StaticHint::NoStaticLinkWithinScope => &mut self.no_static_link_within_scope,
            StaticHint::Unknown => &mut self.unknown,
        };
        *cell = cell.saturating_add(1);
    }
}

/// Raw kernel exe-file identity words from an EXEC record: the raw
/// `s_dev` (`dev_t`, never a userspace `st_dev`) and `i_ino`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExeIdentity {
    pub dev: u64,
    pub ino: u64,
}

impl ExeIdentity {
    /// Both words zero means the kernel recorded nothing: extensive
    /// mode off, an old producer, or a failed kernel read. A zero pair
    /// never addresses a file.
    pub(crate) fn absent(self) -> bool {
        self.dev == 0 && self.ino == 0
    }
}

/// Decode the kernel kdev_t `(major, minor)` pair from a raw `s_dev`
/// word (12-bit major at bits 20–31, 20-bit minor), the same decode
/// the watched-file calibration uses. `libc::major`/`libc::minor`
/// would misread the raw word.
pub(crate) fn kdev_key(dev: u64, ino: u64) -> ObjectKey {
    ObjectKey {
        device: Device {
            major: (dev >> 20) & 0xfff,
            minor: dev & 0xfffff,
        },
        inode: ino,
    }
}

/// One watched provider the Row B name test matches against: the pinned
/// path plus its SONAME bytes, or the path basename when no SONAME is
/// known. Snapshot at attach; SONAMEs and basenames are stable across
/// file replacement, so the snapshot cannot go stale.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WatchedProvider {
    pub path: PathBuf,
    pub soname: Vec<u8>,
}

/// A pending exe identity: seeded from an EXEC record, consumed at most
/// once by a later unmatched exit, in timestamp order. Never bare-PID
/// addressed: seeding requires the producer ticket, and consumption
/// requires the stash timestamp to precede the exit timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StashedExe {
    dev: u64,
    ino: u64,
    exec_ts_ns: u64,
    ticket: u64,
}

/// A cached per-executable verdict with the identity snapshot a hit
/// must reproduce exactly: same file (dev, ino) and unchanged
/// size/mtime/ctime, so an in-place modification never serves stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VerdictEntry {
    hint: StaticHint,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
}

/// Capture-local extensive-mode state. Everything here is discarded at
/// capture end; only [`GapExeHints`] counts are ever published.
#[derive(Debug, Default)]
pub(crate) struct ExtensiveState {
    enabled: bool,
    stash: BTreeMap<u32, StashedExe>,
    path_cache: BTreeMap<ObjectKey, PathBuf>,
    verdicts: BTreeMap<(u64, u64), VerdictEntry>,
    watched: Vec<WatchedProvider>,
    hints: GapExeHints,
    capture_bytes_charged: u64,
    analyses_run: u64,
}

impl ExtensiveState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn set_enabled(&mut self, on: bool) {
        self.enabled = on;
    }

    pub(crate) fn enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn hints(&self) -> &GapExeHints {
        &self.hints
    }

    /// Row A: learn one `(dev, ino)` → path pair from a live scan. First
    /// learned wins (bind-mounted aliases reopen the same file, and the
    /// reopen verify decides); inode 0 and a full cache retain nothing.
    pub(crate) fn learn_scan_path(&mut self, key: ObjectKey, path: &Path) {
        if key.inode == 0 || self.path_cache.contains_key(&key) {
            return;
        }
        if self.path_cache.len() >= HINT_MAX_PATH_CACHE_ENTRIES {
            return;
        }
        self.path_cache.insert(key, path.to_path_buf());
    }

    /// B-RED shell: GREEN seeds the stash from EXEC records.
    pub(crate) fn note_exec_record(&mut self, record: &DiscoveryRecord) {
        let _ = record;
    }

    /// B-RED shell: GREEN drops the stash when a PID is admitted.
    pub(crate) fn drop_stash_for_pid(&mut self, pid: u32) {
        let _ = pid;
    }

    /// B-RED shell: GREEN consumes the stash, analyzes, and counts.
    pub(crate) fn classify_gap(&mut self, record: &DiscoveryRecord) -> StaticHint {
        let _ = record;
        StaticHint::Unknown
    }

    /// B-RED shell: GREEN runs the bounded D-transitive analysis.
    pub(crate) fn analyze_executable(&mut self, dev: u64, ino: u64) -> StaticHint {
        let _ = (dev, ino);
        StaticHint::Unknown
    }

    #[cfg(test)]
    pub(crate) fn set_watched_for_test(&mut self, watched: Vec<WatchedProvider>) {
        self.watched = watched;
    }

    #[cfg(test)]
    pub(crate) fn analyses_run_for_test(&self) -> u64 {
        self.analyses_run
    }

    #[cfg(test)]
    pub(crate) fn capture_bytes_charged_for_test(&self) -> u64 {
        self.capture_bytes_charged
    }

    #[cfg(test)]
    pub(crate) fn verdicts_len_for_test(&self) -> usize {
        self.verdicts.len()
    }

    #[cfg(test)]
    pub(crate) fn path_cache_len_for_test(&self) -> usize {
        self.path_cache.len()
    }
}

/// Row B: the `DT_NEEDED` names and optional `DT_SONAME` of one object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ElfNeeded {
    pub needed: Vec<Vec<u8>>,
    pub soname: Option<Vec<u8>>,
}

/// Why one object's bounded read failed. Every variant voids the
/// analysis to `unknown`; none is ever presented as a partial result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ElfReadFailure {
    Malformed,
    OverBudget,
    NameTooLong,
}

/// B-RED shell: GREEN reads one object's bounded ELF spans.
pub(crate) fn read_elf_needed(
    file: &std::fs::File,
    charge: &mut u64,
) -> Result<ElfNeeded, ElfReadFailure> {
    let _ = (file, charge);
    Err(ElfReadFailure::Malformed)
}

#[cfg(test)]
pub(crate) mod fixture {
    //! Hand-built minimal ELF fixtures with exact `DT_NEEDED`/`DT_SONAME`
    //! control. No toolchain dependency; every byte is asserted.

    use super::*;
    use std::os::unix::fs::MetadataExt as _;

    pub(crate) struct ElfSpec {
        pub needed: Vec<Vec<u8>>,
        pub soname: Option<Vec<u8>>,
        pub bits32: bool,
        pub is_lib: bool,
        pub vaddr_bias: u64,
        pub strtab_pad: usize,
    }

    impl ElfSpec {
        pub(crate) fn exe(needed: &[&[u8]]) -> Self {
            Self {
                needed: needed.iter().map(|name| name.to_vec()).collect(),
                soname: None,
                bits32: false,
                is_lib: false,
                vaddr_bias: 0,
                strtab_pad: 0,
            }
        }

        pub(crate) fn lib(soname: &[u8], needed: &[&[u8]]) -> Self {
            Self {
                needed: needed.iter().map(|name| name.to_vec()).collect(),
                soname: Some(soname.to_vec()),
                bits32: false,
                is_lib: true,
                vaddr_bias: 0,
                strtab_pad: 0,
            }
        }
    }

    fn put_u16(out: &mut Vec<u8>, value: u16) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn put_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn put_u64(out: &mut Vec<u8>, value: u64) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    /// One minimal ELF: header, one `PT_LOAD` covering the file, one
    /// `PT_DYNAMIC`, the dynamic array, and the string table.
    pub(crate) fn build_elf(spec: &ElfSpec) -> Vec<u8> {
        let mut strtab = vec![0u8];
        let mut str_offs: Vec<u64> = Vec::new();
        for name in spec.needed.iter().chain(spec.soname.iter()) {
            str_offs.push(strtab.len() as u64);
            strtab.extend_from_slice(name);
            strtab.push(0);
        }
        strtab.extend(std::iter::repeat_n(0, spec.strtab_pad));
        let dyn_count = spec.needed.len() + usize::from(spec.soname.is_some()) + 3;
        let (ehdr_size, phent_size, dyn_size, dyn_off) = if spec.bits32 {
            (52u64, 32u64, 8u64, 52 + 2 * 32)
        } else {
            (64u64, 56u64, 16u64, 64 + 2 * 56)
        };
        let strtab_off = dyn_off + dyn_count as u64 * dyn_size;
        let total = strtab_off + strtab.len() as u64;
        let bias = spec.vaddr_bias;

        let mut out = Vec::with_capacity(total as usize);
        out.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
        out.push(if spec.bits32 { 1 } else { 2 });
        out.push(1);
        out.push(1);
        out.push(0);
        out.extend_from_slice(&[0u8; 8]);
        put_u16(&mut out, if spec.is_lib { 3 } else { 2 });
        put_u16(&mut out, if spec.bits32 { 3 } else { 62 });
        put_u32(&mut out, 1);
        if spec.bits32 {
            put_u32(&mut out, 0);
            put_u32(&mut out, 52);
            put_u32(&mut out, 0);
        } else {
            put_u64(&mut out, 0);
            put_u64(&mut out, 64);
            put_u64(&mut out, 0);
        }
        put_u32(&mut out, 0);
        put_u16(&mut out, ehdr_size as u16);
        put_u16(&mut out, phent_size as u16);
        put_u16(&mut out, 2);
        put_u16(&mut out, 0);
        put_u16(&mut out, 0);
        put_u16(&mut out, 0);
        if spec.bits32 {
            for (kind, offset) in [(1u32, 0u64), (2u32, dyn_off)] {
                put_u32(&mut out, kind);
                put_u32(&mut out, offset as u32);
                put_u32(&mut out, (bias + offset) as u32);
                put_u32(&mut out, bias as u32);
                put_u32(
                    &mut out,
                    if kind == 1 {
                        total as u32
                    } else {
                        (dyn_count * 8) as u32
                    },
                );
                put_u32(
                    &mut out,
                    if kind == 1 {
                        total as u32
                    } else {
                        (dyn_count * 8) as u32
                    },
                );
                put_u32(&mut out, if kind == 1 { 5 } else { 6 });
                put_u32(&mut out, 0x1000);
            }
            for (index, _) in spec.needed.iter().enumerate() {
                put_u32(&mut out, 1);
                put_u32(&mut out, str_offs[index] as u32);
            }
            if spec.soname.is_some() {
                put_u32(&mut out, 14);
                put_u32(&mut out, str_offs[spec.needed.len()] as u32);
            }
            put_u32(&mut out, 5);
            put_u32(&mut out, (bias + strtab_off) as u32);
            put_u32(&mut out, 10);
            put_u32(&mut out, strtab.len() as u32);
            put_u32(&mut out, 0);
            put_u32(&mut out, 0);
        } else {
            for (kind, offset, filesz) in
                [(1u32, 0u64, total), (2u32, dyn_off, dyn_count as u64 * 16)]
            {
                put_u32(&mut out, kind);
                put_u32(&mut out, if kind == 1 { 5 } else { 6 });
                put_u64(&mut out, offset);
                put_u64(&mut out, bias + offset);
                put_u64(&mut out, bias);
                put_u64(&mut out, filesz);
                put_u64(&mut out, filesz);
                put_u64(&mut out, 0x1000);
            }
            for (index, _) in spec.needed.iter().enumerate() {
                put_u64(&mut out, 1);
                put_u64(&mut out, str_offs[index]);
            }
            if spec.soname.is_some() {
                put_u64(&mut out, 14);
                put_u64(&mut out, str_offs[spec.needed.len()]);
            }
            put_u64(&mut out, 5);
            put_u64(&mut out, bias + strtab_off);
            put_u64(&mut out, 10);
            put_u64(&mut out, strtab.len() as u64);
            put_u64(&mut out, 0);
            put_u64(&mut out, 0);
        }
        out.extend_from_slice(&strtab);
        assert_eq!(out.len() as u64, total, "fixture layout miscomputed");
        out
    }

    pub(crate) fn write_elf(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, bytes).expect("write ELF fixture");
        path
    }

    /// The raw `(s_dev, ino)` pair the kernel would record for an
    /// executable at `path`: `fstat` major/minor recombined into the
    /// kernel kdev_t layout.
    pub(crate) fn record_identity_of(path: &Path) -> (u64, u64) {
        let meta = std::fs::metadata(path).expect("stat ELF fixture");
        let major = u64::from(libc::major(meta.dev()));
        let minor = u64::from(libc::minor(meta.dev()));
        ((major << 20) | minor, meta.ino())
    }

    /// The scan-learned cache key for the file at `path`.
    pub(crate) fn cache_key_of(path: &Path) -> ObjectKey {
        let meta = std::fs::metadata(path).expect("stat ELF fixture");
        ObjectKey {
            device: Device {
                major: u64::from(libc::major(meta.dev())),
                minor: u64::from(libc::minor(meta.dev())),
            },
            inode: meta.ino(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::*;
    use super::*;

    fn watched(path: &Path, soname: &[u8]) -> WatchedProvider {
        WatchedProvider {
            path: path.to_path_buf(),
            soname: soname.to_vec(),
        }
    }

    fn analyzed(
        dir: &Path,
        watched: Vec<WatchedProvider>,
        exe: &Path,
        libs: &[&Path],
    ) -> (StaticHint, ExtensiveState) {
        let mut state = ExtensiveState::new();
        state.set_enabled(true);
        state.set_watched_for_test(watched);
        state.learn_scan_path(cache_key_of(exe), exe);
        for lib in libs {
            state.learn_scan_path(cache_key_of(lib), lib);
        }
        let (dev, ino) = record_identity_of(exe);
        let hint = state.analyze_executable(dev, ino);
        let _ = dir;
        (hint, state)
    }

    #[test]
    fn kdev_key_decodes_kernel_dev() {
        assert_eq!(
            kdev_key(0x103_00001, 802),
            ObjectKey {
                device: Device {
                    major: 0x103,
                    minor: 1
                },
                inode: 802
            }
        );
        assert_eq!(
            kdev_key(0, 0),
            ObjectKey {
                device: Device { major: 0, minor: 0 },
                inode: 0
            }
        );
        // Live round-trip: the recorded pair decodes back to the
        // scan-learned key on this machine's filesystem.
        let dir = tempfile::tempdir().unwrap();
        let exe = write_elf(dir.path(), "rt", &build_elf(&ElfSpec::exe(&[])));
        let (dev, ino) = record_identity_of(&exe);
        assert_eq!(kdev_key(dev, ino), cache_key_of(&exe));
        assert!(!ExeIdentity { dev, ino }.absent());
        assert!(ExeIdentity { dev: 0, ino: 0 }.absent());
    }

    #[test]
    fn learn_scan_path_bounds_cache() {
        let mut state = ExtensiveState::new();
        let key = |inode| ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode,
        };
        state.learn_scan_path(key(0), Path::new("/x"));
        assert_eq!(state.path_cache_len_for_test(), 0);
        state.learn_scan_path(key(7), Path::new("/a"));
        state.learn_scan_path(key(7), Path::new("/b"));
        assert_eq!(state.path_cache_len_for_test(), 1);
        assert_eq!(state.path_cache.get(&key(7)).unwrap(), &PathBuf::from("/a"));
        for inode in 8..8 + HINT_MAX_PATH_CACHE_ENTRIES as u64 {
            state.learn_scan_path(key(inode), Path::new("/f"));
        }
        assert_eq!(state.path_cache_len_for_test(), HINT_MAX_PATH_CACHE_ENTRIES);
    }

    #[test]
    fn elf_needed_parses_direct_entries_64() {
        let dir = tempfile::tempdir().unwrap();
        let provider = write_elf(
            dir.path(),
            "libprov.so.1",
            &build_elf(&ElfSpec::lib(b"libprov.so.1", &[])),
        );
        let exe = write_elf(
            dir.path(),
            "exe",
            &build_elf(&ElfSpec::exe(&[b"libprov.so.1"])),
        );
        let (hint, state) = analyzed(
            dir.path(),
            vec![watched(&provider, b"libprov.so.1")],
            &exe,
            &[&provider],
        );
        assert_eq!(hint, StaticHint::LinksProvider);
        assert_eq!(state.analyses_run_for_test(), 1);
        assert!(state.capture_bytes_charged_for_test() > 0);
        assert_eq!(state.verdicts_len_for_test(), 1);
    }

    #[test]
    fn elf_needed_parses_direct_entries_32() {
        let dir = tempfile::tempdir().unwrap();
        let mut provider_spec = ElfSpec::lib(b"libprov.so.1", &[]);
        provider_spec.bits32 = true;
        provider_spec.vaddr_bias = 0x8048_000;
        let mut exe_spec = ElfSpec::exe(&[b"libprov.so.1"]);
        exe_spec.bits32 = true;
        exe_spec.vaddr_bias = 0x8048_000;
        let provider = write_elf(dir.path(), "libprov.so", &build_elf(&provider_spec));
        let exe = write_elf(dir.path(), "exe32", &build_elf(&exe_spec));
        let (hint, state) = analyzed(
            dir.path(),
            vec![watched(&provider, b"libprov.so.1")],
            &exe,
            &[&provider],
        );
        assert_eq!(hint, StaticHint::LinksProvider);
        assert_eq!(state.analyses_run_for_test(), 1);
    }

    #[test]
    fn elf_needed_biased_vaddr_translates_strtab() {
        let dir = tempfile::tempdir().unwrap();
        let mut spec = ElfSpec::exe(&[b"libprov.so.1"]);
        spec.vaddr_bias = 0x400_000;
        let provider = write_elf(
            dir.path(),
            "libprov.so.1",
            &build_elf(&ElfSpec::lib(b"libprov.so.1", &[])),
        );
        let exe = write_elf(dir.path(), "exeb", &build_elf(&spec));
        let (hint, _) = analyzed(
            dir.path(),
            vec![watched(&provider, b"libprov.so.1")],
            &exe,
            &[&provider],
        );
        assert_eq!(hint, StaticHint::LinksProvider);
    }

    #[test]
    fn elf_needed_transitive_depth2_links_provider() {
        let dir = tempfile::tempdir().unwrap();
        let provider = write_elf(
            dir.path(),
            "libprov.so.1",
            &build_elf(&ElfSpec::lib(b"libprov.so.1", &[])),
        );
        let helper = write_elf(
            dir.path(),
            "libhelper.so.1",
            &build_elf(&ElfSpec::lib(b"libhelper.so.1", &[b"libprov.so.1"])),
        );
        let exe = write_elf(
            dir.path(),
            "exe",
            &build_elf(&ElfSpec::exe(&[b"libhelper.so.1"])),
        );
        let (hint, _) = analyzed(
            dir.path(),
            vec![watched(&provider, b"libprov.so.1")],
            &exe,
            &[&provider, &helper],
        );
        assert_eq!(hint, StaticHint::LinksProvider);
    }

    #[test]
    fn elf_needed_loader_soname_links_loader() {
        let dir = tempfile::tempdir().unwrap();
        let exe = write_elf(
            dir.path(),
            "exe",
            &build_elf(&ElfSpec::exe(&[b"libp11-kit.so.0"])),
        );
        let (hint, _) = analyzed(dir.path(), vec![], &exe, &[]);
        assert_eq!(hint, StaticHint::LinksPkcs11Loader);
    }

    #[test]
    fn elf_needed_provider_wins_over_loader() {
        let dir = tempfile::tempdir().unwrap();
        let provider = write_elf(
            dir.path(),
            "libprov.so.1",
            &build_elf(&ElfSpec::lib(b"libprov.so.1", &[])),
        );
        let exe = write_elf(
            dir.path(),
            "exe",
            &build_elf(&ElfSpec::exe(&[b"libp11-kit.so.0", b"libprov.so.1"])),
        );
        let (hint, _) = analyzed(
            dir.path(),
            vec![watched(&provider, b"libprov.so.1")],
            &exe,
            &[&provider],
        );
        assert_eq!(hint, StaticHint::LinksProvider);
    }

    #[test]
    fn elf_needed_unpinned_provider_name_proves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let evil = write_elf(
            dir.path(),
            "evilprov.so",
            &build_elf(&ElfSpec::lib(b"evilprov.so", &[])),
        );
        let exe = write_elf(
            dir.path(),
            "exe",
            &build_elf(&ElfSpec::exe(&[b"evilprov.so"])),
        );
        // Resolvable and well-formed, but not a watched provider.
        let (hint, _) = analyzed(dir.path(), vec![], &exe, &[&evil]);
        assert_eq!(hint, StaticHint::NoStaticLinkWithinScope);
    }

    #[test]
    fn elf_needed_depth3_provider_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let provider = write_elf(
            dir.path(),
            "libprov.so.1",
            &build_elf(&ElfSpec::lib(b"libprov.so.1", &[])),
        );
        let deep = write_elf(
            dir.path(),
            "libdeep.so",
            &build_elf(&ElfSpec::lib(b"libdeep.so", &[b"libprov.so.1"])),
        );
        let middle = write_elf(
            dir.path(),
            "libmid.so",
            &build_elf(&ElfSpec::lib(b"libmid.so", &[b"libdeep.so"])),
        );
        let exe = write_elf(
            dir.path(),
            "exe",
            &build_elf(&ElfSpec::exe(&[b"libmid.so"])),
        );
        // The provider name sits in libdeep (depth 3): out of scope,
        // so the in-scope set is complete without it.
        let (hint, _) = analyzed(
            dir.path(),
            vec![watched(&provider, b"libprov.so.1")],
            &exe,
            &[&provider, &middle, &deep],
        );
        assert_eq!(hint, StaticHint::NoStaticLinkWithinScope);
    }

    #[test]
    fn elf_needed_cycle_terminates() {
        let dir = tempfile::tempdir().unwrap();
        let liba = write_elf(
            dir.path(),
            "liba.so",
            &build_elf(&ElfSpec::lib(b"liba.so", &[b"libb.so"])),
        );
        let libb = write_elf(
            dir.path(),
            "libb.so",
            &build_elf(&ElfSpec::lib(b"libb.so", &[b"liba.so"])),
        );
        let exe = write_elf(dir.path(), "exe", &build_elf(&ElfSpec::exe(&[b"liba.so"])));
        let (hint, _) = analyzed(dir.path(), vec![], &exe, &[&liba, &libb]);
        assert_eq!(hint, StaticHint::NoStaticLinkWithinScope);
    }

    #[test]
    fn elf_needed_static_exe_has_no_link() {
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = build_elf(&ElfSpec::exe(&[]));
        // Well-formed headers, zero program headers: no dynamic
        // section, so the in-scope needed set is empty and complete.
        bytes[56] = 0;
        bytes[57] = 0;
        let exe = write_elf(dir.path(), "static", &bytes);
        let (hint, _) = analyzed(dir.path(), vec![], &exe, &[]);
        assert_eq!(hint, StaticHint::NoStaticLinkWithinScope);
    }

    #[test]
    fn elf_needed_dlopen_only_stays_no_static_link() {
        let dir = tempfile::tempdir().unwrap();
        let provider = write_elf(
            dir.path(),
            "libprov.so.1",
            &build_elf(&ElfSpec::lib(b"libprov.so.1", &[])),
        );
        // A dlopen-only user names only libc: the provider is
        // invisible by design, honestly negative.
        let exe = write_elf(
            dir.path(),
            "exe",
            &build_elf(&ElfSpec::exe(&[b"libc.so.6"])),
        );
        let (hint, _) = analyzed(
            dir.path(),
            vec![watched(&provider, b"libprov.so.1")],
            &exe,
            &[&provider],
        );
        // libc.so.6 is unresolvable here, so this fixture would be
        // unknown; resolve it with a stub to prove the negative.
        let _ = hint;
        let libc = write_elf(
            dir.path(),
            "libc.so.6",
            &build_elf(&ElfSpec::lib(b"libc.so.6", &[])),
        );
        let (hint, _) = analyzed(
            dir.path(),
            vec![watched(&provider, b"libprov.so.1")],
            &exe,
            &[&provider, &libc],
        );
        assert_eq!(hint, StaticHint::NoStaticLinkWithinScope);
    }

    #[test]
    fn elf_needed_rejects_truncated_dynamic() {
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = build_elf(&ElfSpec::exe(&[b"libprov.so.1"]));
        bytes.truncate(bytes.len() / 2);
        let exe = write_elf(dir.path(), "trunc", &bytes);
        let (hint, state) = analyzed(dir.path(), vec![], &exe, &[]);
        assert_eq!(hint, StaticHint::Unknown);
        assert!(state.capture_bytes_charged_for_test() > 0);
        assert_eq!(state.analyses_run_for_test(), 1);
    }

    #[test]
    fn elf_needed_rejects_bad_magic() {
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = build_elf(&ElfSpec::exe(&[]));
        bytes[0] = 0;
        let exe = write_elf(dir.path(), "bad", &bytes);
        let (hint, state) = analyzed(dir.path(), vec![], &exe, &[]);
        assert_eq!(hint, StaticHint::Unknown);
        assert_eq!(state.analyses_run_for_test(), 1);
    }

    #[test]
    fn elf_needed_name_length_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let ok_name = vec![b'n'; 255];
        let exe_ok = write_elf(
            dir.path(),
            "ok255",
            &build_elf(&ElfSpec::exe(&[ok_name.as_slice()])),
        );
        let stub_file = write_elf(
            dir.path(),
            "stub255",
            &build_elf(&ElfSpec::lib(&ok_name, &[])),
        );
        // The stub file itself carries the 255-byte basename, so the
        // name resolves and the negative completes.
        let ok_str = std::str::from_utf8(&ok_name).unwrap().to_string();
        let stub = dir.path().join(&ok_str);
        std::fs::rename(&stub_file, &stub).unwrap();
        let (hint, _) = analyzed(dir.path(), vec![], &exe_ok, &[&stub]);
        assert_eq!(hint, StaticHint::NoStaticLinkWithinScope);

        let long_name = vec![b'n'; 256];
        let exe_long = write_elf(
            dir.path(),
            "ok256",
            &build_elf(&ElfSpec::exe(&[long_name.as_slice()])),
        );
        let (hint, _) = analyzed(dir.path(), vec![], &exe_long, &[]);
        assert_eq!(hint, StaticHint::Unknown);
    }

    #[test]
    fn elf_needed_object_budget_voids_analysis() {
        let dir = tempfile::tempdir().unwrap();
        // A 40-deep chain of distinct libs: object 33 exceeds the
        // 32-object budget. Depth caps the walk first unless the
        // objects fan out at depth 1, so hang 40 libs off the exe.
        let mut names: Vec<Vec<u8>> = Vec::new();
        let mut libs: Vec<PathBuf> = Vec::new();
        for index in 0..40 {
            let name = format!("libf{index:02}.so").into_bytes();
            let lib = write_elf(
                dir.path(),
                &format!("libf{index:02}.so"),
                &build_elf(&ElfSpec::lib(&name, &[])),
            );
            names.push(name);
            libs.push(lib);
        }
        let refs: Vec<&[u8]> = names.iter().map(Vec::as_slice).collect();
        let exe = write_elf(dir.path(), "fan", &build_elf(&ElfSpec::exe(&refs)));
        let lib_refs: Vec<&Path> = libs.iter().map(PathBuf::as_path).collect();
        let (hint, state) = analyzed(dir.path(), vec![], &exe, &lib_refs);
        assert_eq!(hint, StaticHint::Unknown);
        assert_eq!(state.analyses_run_for_test(), 1);
    }

    #[test]
    fn elf_needed_edge_budget_voids_analysis() {
        let dir = tempfile::tempdir().unwrap();
        let names: Vec<Vec<u8>> = (0..129)
            .map(|index| format!("libg{index:03}.so").into_bytes())
            .collect();
        let refs: Vec<&[u8]> = names.iter().map(Vec::as_slice).collect();
        let exe = write_elf(dir.path(), "edges", &build_elf(&ElfSpec::exe(&refs)));
        // All unresolvable: the 129th examined edge exceeds the
        // 128-edge budget before the set completes.
        let (hint, state) = analyzed(dir.path(), vec![], &exe, &[]);
        assert_eq!(hint, StaticHint::Unknown);
        assert_eq!(state.analyses_run_for_test(), 1);
    }

    #[test]
    fn elf_needed_exe_byte_budget_voids_analysis() {
        let dir = tempfile::tempdir().unwrap();
        let mut spec = ElfSpec::exe(&[b"libprov.so.1"]);
        spec.strtab_pad = 2 * 1024 * 1024;
        let exe = write_elf(dir.path(), "big", &build_elf(&spec));
        let (hint, state) = analyzed(dir.path(), vec![], &exe, &[]);
        assert_eq!(hint, StaticHint::Unknown);
        assert_eq!(state.analyses_run_for_test(), 1);
    }

    #[test]
    fn elf_needed_capture_byte_budget_voids_analysis() {
        let dir = tempfile::tempdir().unwrap();
        let exe = write_elf(dir.path(), "exe", &build_elf(&ElfSpec::exe(&[])));
        let exe2 = write_elf(dir.path(), "exe2", &build_elf(&ElfSpec::exe(&[])));
        let mut state = ExtensiveState::new();
        state.set_enabled(true);
        state.learn_scan_path(cache_key_of(&exe), &exe);
        state.learn_scan_path(cache_key_of(&exe2), &exe2);
        let (dev, ino) = record_identity_of(&exe);
        assert_eq!(
            state.analyze_executable(dev, ino),
            StaticHint::NoStaticLinkWithinScope
        );
        assert_eq!(state.analyses_run_for_test(), 1);
        // A spent capture budget refuses the next miss before any
        // work; the earlier analysis is unaffected.
        state.capture_bytes_charged = HINT_MAX_BYTES_PER_CAPTURE;
        let (dev2, ino2) = record_identity_of(&exe2);
        assert_eq!(state.analyze_executable(dev2, ino2), StaticHint::Unknown);
        assert_eq!(state.analyses_run_for_test(), 1);
    }

    #[test]
    fn elf_needed_unresolvable_branch_voids_only_negative() {
        let dir = tempfile::tempdir().unwrap();
        let exe = write_elf(
            dir.path(),
            "exe",
            &build_elf(&ElfSpec::exe(&[b"libmissing.so.9"])),
        );
        let (hint, state) = analyzed(dir.path(), vec![], &exe, &[]);
        assert_eq!(hint, StaticHint::Unknown);
        assert_eq!(state.analyses_run_for_test(), 1);
    }

    #[test]
    fn elf_needed_positive_survives_unresolved_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let provider = write_elf(
            dir.path(),
            "libprov.so.1",
            &build_elf(&ElfSpec::lib(b"libprov.so.1", &[])),
        );
        let exe = write_elf(
            dir.path(),
            "exe",
            &build_elf(&ElfSpec::exe(&[b"libmissing.so.9", b"libprov.so.1"])),
        );
        let (hint, _) = analyzed(
            dir.path(),
            vec![watched(&provider, b"libprov.so.1")],
            &exe,
            &[&provider],
        );
        assert_eq!(hint, StaticHint::LinksProvider);
    }

    #[test]
    fn elf_needed_loader_witness_survives_later_overbudget() {
        let dir = tempfile::tempdir().unwrap();
        let mut names: Vec<Vec<u8>> = vec![b"libp11-kit.so.0".to_vec()];
        names.extend((0..129).map(|index| format!("libh{index:03}.so").into_bytes()));
        let refs: Vec<&[u8]> = names.iter().map(Vec::as_slice).collect();
        let exe = write_elf(dir.path(), "mixed", &build_elf(&ElfSpec::exe(&refs)));
        // The loader chain completed within budget before the edge
        // budget blew; the complete witness stands.
        let (hint, _) = analyzed(dir.path(), vec![], &exe, &[]);
        assert_eq!(hint, StaticHint::LinksPkcs11Loader);
    }

    #[test]
    fn elf_needed_verdict_cache_hit_skips_reparse() {
        let dir = tempfile::tempdir().unwrap();
        let provider = write_elf(
            dir.path(),
            "libprov.so.1",
            &build_elf(&ElfSpec::lib(b"libprov.so.1", &[])),
        );
        let exe = write_elf(
            dir.path(),
            "exe",
            &build_elf(&ElfSpec::exe(&[b"libprov.so.1"])),
        );
        let mut state = ExtensiveState::new();
        state.set_enabled(true);
        state.set_watched_for_test(vec![watched(&provider, b"libprov.so.1")]);
        state.learn_scan_path(cache_key_of(&exe), &exe);
        state.learn_scan_path(cache_key_of(&provider), &provider);
        let (dev, ino) = record_identity_of(&exe);
        assert_eq!(
            state.analyze_executable(dev, ino),
            StaticHint::LinksProvider
        );
        assert_eq!(
            state.analyze_executable(dev, ino),
            StaticHint::LinksProvider
        );
        assert_eq!(state.analyses_run_for_test(), 1);
        assert_eq!(state.verdicts_len_for_test(), 1);
    }

    #[test]
    fn elf_needed_changed_file_refuses_cache_hit() {
        let dir = tempfile::tempdir().unwrap();
        let exe = write_elf(dir.path(), "exe", &build_elf(&ElfSpec::exe(&[])));
        let mut state = ExtensiveState::new();
        state.set_enabled(true);
        state.learn_scan_path(cache_key_of(&exe), &exe);
        let (dev, ino) = record_identity_of(&exe);
        assert_eq!(
            state.analyze_executable(dev, ino),
            StaticHint::NoStaticLinkWithinScope
        );
        // Same path and inode, new bytes: the snapshot mismatches,
        // so the hit is refused and the file is re-analyzed.
        std::fs::write(&exe, build_elf(&ElfSpec::exe(&[]))).unwrap();
        assert_eq!(
            state.analyze_executable(dev, ino),
            StaticHint::NoStaticLinkWithinScope
        );
        assert_eq!(state.analyses_run_for_test(), 2);
    }

    #[test]
    fn elf_needed_replaced_path_refuses_stale_key() {
        let dir = tempfile::tempdir().unwrap();
        let exe = write_elf(dir.path(), "exe", &build_elf(&ElfSpec::exe(&[])));
        let mut state = ExtensiveState::new();
        state.set_enabled(true);
        state.learn_scan_path(cache_key_of(&exe), &exe);
        let (dev, ino) = record_identity_of(&exe);
        std::fs::remove_file(&exe).unwrap();
        std::fs::write(&exe, build_elf(&ElfSpec::exe(&[]))).unwrap();
        let (new_dev, new_ino) = record_identity_of(&exe);
        assert_ne!((dev, ino), (new_dev, new_ino), "replacement kept identity");
        assert_eq!(state.analyze_executable(dev, ino), StaticHint::Unknown);
        assert_eq!(state.analyses_run_for_test(), 1);
    }
}
