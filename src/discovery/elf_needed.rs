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

use crate::discovery::identity::PinnedObjects;
use crate::process::ProcessView;
use p11scope_ebpf_common::DiscoveryRecord;
use p11scope_manifest::identity::open_regular;
use p11scope_manifest::maps::{Device, ObjectKey};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};

/// Row D (D-transitive): the executable is depth 0, its `DT_NEEDED`
/// names are name-tested and resolved at depth 1, their names at depth 2.
/// Depth-2 objects are opened, identity-verified, parsed, and
/// SONAME-checked, but their own names are never examined: a provider
/// named only past depth 2 is out of scope, and the in-scope set
/// completes without it.
pub(crate) const HINT_MAX_DEPTH: u32 = 2;
/// Row D: at most 32 ELF objects opened per analysis, counting the
/// executable and every candidate attempt (failed parses and
/// SONAME mismatches included), reserved before each open.
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

/// Row C: the finite per-gap hint classes. The publication keys
/// (`links_provider`, `links_pkcs11_loader`,
/// `no_static_link_within_scope`, `unknown`) live with the renderer;
/// analysis compares variants, never strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StaticHint {
    LinksProvider,
    LinksPkcs11Loader,
    NoStaticLinkWithinScope,
    Unknown,
}

/// Row C: per-gap classification counts. The four counts sum to the
/// analyzed unmatched-exit subpopulation, never to `pid_descendant_gaps`
/// itself (admissions and overflow sentinels carry no hint). Nominally
/// `pub` for the `render::Evidence` field; the module stays
/// `pub(crate)`, so no new nameable public API escapes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GapExeHints {
    pub links_provider: u64,
    pub links_pkcs11_loader: u64,
    pub no_static_link_within_scope: u64,
    pub unknown: u64,
}

impl GapExeHints {
    /// Test-assertion API: production render emits the four counts, no
    /// total, so this stays out of non-test builds.
    #[cfg(test)]
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

/// Row A scan sink: learn one scanned view's executable `(dev, ino)`
/// → path pair while its generation pin holds. The readlink and the
/// `fstat` run inside the same `run_while_same` bracket as the scan's
/// own exe read, so a reused PID fails the bracket instead of teaching
/// a wrong pair; the analysis re-verifies on reopen either way.
/// Silent on every failure: an unlearned binary classifies `unknown`,
/// never guessed. A free function so scan sites holding
/// `&self.views[..]` can pass disjoint field borrows.
pub(crate) fn learn_view_exe(state: &mut ExtensiveState, view: &ProcessView) {
    if !state.enabled() {
        return;
    }
    let pid = view.pid();
    let learned = view.run_while_same(|| {
        let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
        let meta = std::fs::metadata(&path).ok()?;
        let key = cache_key_of_metadata(&meta);
        Some((key, path))
    });
    if let Ok(Some((key, path))) = learned {
        state.learn_scan_path(key, &path);
    }
}

/// The scan-learned cache key for `fstat` metadata: the same
/// major/minor/inode triple [`kdev_key`] decodes the kernel pair into,
/// so a recorded pair meets its learned path.
pub(crate) fn cache_key_of_metadata(meta: &std::fs::Metadata) -> ObjectKey {
    ObjectKey {
        device: Device {
            major: u64::from(libc::major(meta.dev())),
            minor: u64::from(libc::minor(meta.dev())),
        },
        inode: meta.ino(),
    }
}

/// One watched provider the Row B name test matches against: the pinned
/// path plus its SONAME bytes, or the path basename when no SONAME is
/// known. Snapshot at attach; SONAMEs and basenames are stable across
/// file replacement, so the name test cannot go stale. The raw
/// `(dev, ino)` pair re-verifies the pinned path on every reopen, so an
/// edge followed into a replaced file voids instead of misreading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WatchedProvider {
    pub path: PathBuf,
    pub soname: Vec<u8>,
    pub dev: u64,
    pub ino: u64,
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
}

/// One dependency object whose parsed content supports a cached
/// verdict: its recorded identity plus the size/mtime/ctime snapshot
/// taken inside its stability bracket. A cache hit must reproduce
/// every recorded snapshot exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DepProof {
    dev: u64,
    ino: u64,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
}

/// A cached per-executable verdict with the identity snapshot a hit
/// must reproduce exactly: same file (dev, ino) and unchanged
/// size/mtime/ctime, so an in-place modification never serves stale.
/// Transitive verdicts also carry every intermediate dependency
/// snapshot, the candidate count each resolution chose from, and the
/// effective watched-name list the name test used: a hit revalidates
/// all of it, so a changed, removed or newly shadowed dependency
/// refuses the hit instead of serving stale. Only completed
/// non-`unknown` verdicts from a clean walk (no failed candidate
/// attempts, no latched early verdict) are cached: `unknown` means
/// the in-scope set never completed, and a later scan may learn the
/// missing path, so an `unknown` is always re-attempted.
#[derive(Debug, Clone, PartialEq, Eq)]
struct VerdictEntry {
    hint: StaticHint,
    size: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
    deps: Vec<DepProof>,
    resolutions: Vec<(Vec<u8>, usize)>,
    watched_names: Vec<Vec<u8>>,
}

/// Per-walk accounting and cache proof: objects reserved so far
/// (the executable counts as the first), the dependency snapshots
/// behind the verdict, the candidate count per resolved name, and
/// whether the walk stayed clean enough for its verdict to be
/// cacheable under revalidation.
#[derive(Debug, Default)]
struct WalkProof {
    objects: usize,
    deps: Vec<DepProof>,
    resolutions: Vec<(Vec<u8>, usize)>,
    clean: bool,
}

/// The raw `(dev, ino)` pair the kernel records for the file behind an
/// open handle: `fstat` major/minor recombined into the kernel kdev_t
/// layout plus the inode. Comparing this against the recorded pair is
/// the same-file proof; the path alone never is.
fn identity_of(file: &File) -> std::io::Result<(u64, u64)> {
    let meta = file.metadata()?;
    let major = u64::from(libc::major(meta.dev()));
    let minor = u64::from(libc::minor(meta.dev()));
    Ok(((major << 20) | minor, meta.ino()))
}

fn snapshot_of(file: &File) -> std::io::Result<(u64, i64, i64, i64, i64)> {
    let meta = file.metadata()?;
    Ok((
        meta.size(),
        meta.mtime(),
        meta.mtime_nsec(),
        meta.ctime(),
        meta.ctime_nsec(),
    ))
}

fn path_basename(path: &Path) -> Option<&[u8]> {
    path.file_name().map(|name| name.as_bytes())
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
    /// Test-only mid-analysis mutation hooks (P2-1 stability RED).
    /// Production leaves these `None`/false; tests set them to force a
    /// pre/post snapshot mismatch or an unavailable snapshot between the
    /// brackets, deterministically exercising the Row A stability gate.
    #[cfg(test)]
    pub(crate) test_exe_mutator: Option<fn(&Path)>,
    #[cfg(test)]
    pub(crate) test_intermediate_mutator: Option<fn(&Path)>,
    #[cfg(test)]
    pub(crate) test_fail_exe_pre_snapshot: bool,
    #[cfg(test)]
    pub(crate) test_fail_exe_post_snapshot: bool,
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
    /// Disabled captures learn nothing: the cache is extensive-mode
    /// scratch, and a wrong early learn would shadow a later right one.
    pub(crate) fn learn_scan_path(&mut self, key: ObjectKey, path: &Path) {
        if !self.enabled {
            return;
        }
        if key.inode == 0 || self.path_cache.contains_key(&key) {
            return;
        }
        if self.path_cache.len() >= HINT_MAX_PATH_CACHE_ENTRIES {
            return;
        }
        self.path_cache.insert(key, path.to_path_buf());
    }

    /// Row B: snapshot every pinned object as a watched provider: the
    /// observer-openable attach path, the SONAME parsed from the pinned
    /// handle, and the `fstat` identity for reopen verification.
    /// Degrades gracefully, never fails the capture: an unopenable path
    /// becomes empty (never a resolve candidate, still name-tested when
    /// a SONAME parsed), an unreadable handle becomes `(0, 0)` with an
    /// empty SONAME (basename-tested only, never resolvable). Snapshot
    /// spans charge the capture byte budget like any examined spans.
    pub(crate) fn snapshot_watched(&mut self, pinned: &PinnedObjects) {
        let ids: Vec<_> = pinned.pinned().map(|summary| summary.id).collect();
        let mut watched = Vec::with_capacity(ids.len());
        for id in ids {
            let path = pinned.attach_path_for(id).unwrap_or_default();
            let (dev, ino, soname) = match pinned.file_for(id) {
                Some(file) => {
                    let identity = identity_of(file).unwrap_or((0, 0));
                    let mut charge = 0u64;
                    let soname = read_elf_needed(file, &mut charge, self.capture_bytes_charged)
                        .map(|parsed| parsed.soname.unwrap_or_default())
                        .unwrap_or_default();
                    self.capture_bytes_charged = self.capture_bytes_charged.saturating_add(charge);
                    (identity.0, identity.1, soname)
                }
                None => (0, 0, Vec::new()),
            };
            watched.push(WatchedProvider {
                path,
                soname,
                dev,
                ino,
            });
        }
        self.watched = watched;
    }

    /// Row A: seed one pending exe identity from an EXEC record. The
    /// stash is never bare-PID addressed: seeding requires the nonzero
    /// producer ticket, and consumption requires the stash timestamp to
    /// precede the exit timestamp. A re-exec overwrites (latest wins);
    /// a full stash evicts the smallest PID first (deterministic).
    pub(crate) fn note_exec_record(&mut self, record: &DiscoveryRecord) {
        if !self.enabled || record.binding_id == 0 {
            return;
        }
        let pid = (record.pid_tgid >> 32) as u32;
        if self.stash.len() >= HINT_MAX_EXE_STASH_ENTRIES && !self.stash.contains_key(&pid) {
            self.stash.pop_first();
        }
        self.stash.insert(
            pid,
            StashedExe {
                dev: record.pointers[0],
                ino: record.pointers[1],
                exec_ts_ns: record.hook_ts_ns,
            },
        );
    }

    /// An admitted PID's exits match its admission, never a gap, so its
    /// stash entry is dead. Dropping it also bounds the stash against
    /// long-lived processes that never gap.
    pub(crate) fn drop_stash_for_pid(&mut self, pid: u32) {
        self.stash.remove(&pid);
    }

    /// Row C: consume the stash for one novel unmatched exit and count
    /// exactly one hint. Consume-once: the entry is removed whether or
    /// not the analysis completes. A missing entry, a reordered entry
    /// (stash timestamp at or past the exit timestamp), or an absent
    /// exe pair counts `unknown` without analysis. Disabled captures
    /// neither consume nor count.
    pub(crate) fn classify_gap(&mut self, record: &DiscoveryRecord) -> StaticHint {
        if !self.enabled {
            return StaticHint::Unknown;
        }
        let pid = (record.pid_tgid >> 32) as u32;
        let stashed = self.stash.remove(&pid);
        let hint = match stashed {
            Some(stashed)
                if stashed.exec_ts_ns < record.hook_ts_ns
                    && !ExeIdentity {
                        dev: stashed.dev,
                        ino: stashed.ino,
                    }
                    .absent() =>
            {
                self.analyze_executable(stashed.dev, stashed.ino)
            }
            _ => StaticHint::Unknown,
        };
        self.hints.count(hint);
        hint
    }

    /// Row B/D: run the bounded D-transitive analysis for one recorded
    /// `(dev, ino)` pair. A spent capture budget refuses before any work
    /// (no analysis counted); a verdict-cache hit with current same-file
    /// proof skips the reparse; anything else opens and verifies the
    /// executable (one analysis counted) and walks it.
    pub(crate) fn analyze_executable(&mut self, dev: u64, ino: u64) -> StaticHint {
        if !self.enabled || self.capture_bytes_charged >= HINT_MAX_BYTES_PER_CAPTURE {
            return StaticHint::Unknown;
        }
        if let Some(entry) = self.verdicts.get(&(dev, ino)).cloned()
            && entry.hint != StaticHint::Unknown
            && self.verify_entry(dev, ino, &entry)
        {
            return entry.hint;
        }
        // A stale or non-cacheable entry never serves; drop it so a
        // voided re-analysis cannot resurrect it.
        self.verdicts.remove(&(dev, ino));
        self.analyses_run = self.analyses_run.saturating_add(1);
        let path = self.path_cache.get(&kdev_key(dev, ino)).cloned();
        let Some(path) = path else {
            return StaticHint::Unknown;
        };
        // FIFO-safe open: O_PATH-pin, refuse non-regular, then read the
        // same inode. A plain open would block on a writerless FIFO
        // before the identity check below could refuse it.
        let Ok(exe) = open_regular(&path) else {
            return StaticHint::Unknown;
        };
        let Ok(identity) = identity_of(&exe) else {
            return StaticHint::Unknown;
        };
        if identity != (dev, ino) {
            return StaticHint::Unknown;
        }
        // Row A: the opened FD's stability bracket gates the
        // publication, not just caching. Changed or unavailable
        // identity voids to Unknown and inserts nothing.
        #[cfg(test)]
        let pre = if self.test_fail_exe_pre_snapshot {
            None
        } else {
            snapshot_of(&exe).ok()
        };
        #[cfg(not(test))]
        let pre = snapshot_of(&exe).ok();
        let Some(pre) = pre else {
            return StaticHint::Unknown;
        };
        let (hint, proof) = self.walk_dependencies(&exe, dev, ino);
        #[cfg(test)]
        if let Some(mutate) = self.test_exe_mutator {
            mutate(&path);
        }
        #[cfg(test)]
        let post = if self.test_fail_exe_post_snapshot {
            Err(std::io::Error::other("injected post-snapshot failure"))
        } else {
            snapshot_of(&exe)
        };
        #[cfg(not(test))]
        let post = snapshot_of(&exe);
        let Ok(post) = post else {
            return StaticHint::Unknown;
        };
        if pre != post {
            return StaticHint::Unknown;
        }
        // Cache only completed non-unknown verdicts from a clean walk
        // (its dependency proof revalidates on a hit), and only while
        // the cache has room (a full cache serves hits but retains
        // nothing new).
        if hint != StaticHint::Unknown
            && proof.clean
            && self.verdicts.len() < HINT_MAX_VERDICT_CACHE_ENTRIES
        {
            self.verdicts.insert(
                (dev, ino),
                VerdictEntry {
                    hint,
                    size: pre.0,
                    mtime_sec: pre.1,
                    mtime_nsec: pre.2,
                    ctime_sec: pre.3,
                    ctime_nsec: pre.4,
                    deps: proof.deps,
                    resolutions: proof.resolutions,
                    watched_names: self.effective_watched_names(),
                },
            );
        }
        hint
    }

    /// The learned or pinned path for one recorded `(dev, ino)` pair,
    /// when this capture still knows one.
    fn learned_path(&self, dev: u64, ino: u64) -> Option<PathBuf> {
        if let Some(path) = self.path_cache.get(&kdev_key(dev, ino)) {
            return Some(path.clone());
        }
        self.watched
            .iter()
            .find(|provider| (provider.dev, provider.ino) == (dev, ino))
            .map(|provider| provider.path.clone())
    }

    /// Reopen the known path and demand the recorded identity plus
    /// the recorded size/mtime/ctime snapshot. This is the same-file
    /// proof a cache hit demands of the executable and of every
    /// dependency behind a transitive verdict; anything else refuses.
    /// The reopen is not a custody grant: it supplies no birth,
    /// admission, or absence authority.
    fn verify_unchanged(&self, dev: u64, ino: u64, snapshot: (u64, i64, i64, i64, i64)) -> bool {
        let Some(path) = self.learned_path(dev, ino) else {
            return false;
        };
        // FIFO-safe open (see analyze_executable): a plain open would
        // block on a writerless FIFO before identity could refuse it.
        let Ok(file) = open_regular(&path) else {
            return false;
        };
        let Ok(identity) = identity_of(&file) else {
            return false;
        };
        if identity != (dev, ino) {
            return false;
        }
        snapshot_of(&file).is_ok_and(|snap| snap == snapshot)
    }

    /// A cache hit must reproduce the whole recorded basis: the
    /// effective watched-name list the name test used, the candidate
    /// count every resolution chose from (a newly learned candidate
    /// could shadow the recorded choice), the executable snapshot,
    /// and every intermediate dependency snapshot. Any mismatch,
    /// change or removal refuses the hit and the caller re-analyzes.
    fn verify_entry(&self, dev: u64, ino: u64, entry: &VerdictEntry) -> bool {
        if self.effective_watched_names() != entry.watched_names {
            return false;
        }
        if entry
            .resolutions
            .iter()
            .any(|(name, count)| self.candidates_for(name).len() != *count)
        {
            return false;
        }
        let exe = (
            entry.size,
            entry.mtime_sec,
            entry.mtime_nsec,
            entry.ctime_sec,
            entry.ctime_nsec,
        );
        self.verify_unchanged(dev, ino, exe)
            && entry.deps.iter().all(|dep| {
                self.verify_unchanged(
                    dep.dev,
                    dep.ino,
                    (
                        dep.size,
                        dep.mtime_sec,
                        dep.mtime_nsec,
                        dep.ctime_sec,
                        dep.ctime_nsec,
                    ),
                )
            })
    }

    /// The name each watched provider contributes to the Row B name
    /// test, in watched order: its SONAME when known, else its
    /// pinned-path basename.
    fn effective_watched_names(&self) -> Vec<Vec<u8>> {
        self.watched
            .iter()
            .map(|provider| {
                if provider.soname.is_empty() {
                    path_basename(&provider.path).unwrap_or(&[]).to_vec()
                } else {
                    provider.soname.clone()
                }
            })
            .collect()
    }

    /// Row B resolution candidates for one needed name, in the
    /// deterministic order resolution tries them: basename matches
    /// over the scan-learned path cache, then the pinned watched
    /// paths. No RUNPATH, no loader search, no directory walks.
    fn candidates_for(&self, name: &[u8]) -> Vec<(PathBuf, (u64, u64))> {
        let mut candidates: Vec<(PathBuf, (u64, u64))> = Vec::new();
        for (key, path) in &self.path_cache {
            if path_basename(path).is_some_and(|base| base == name) {
                let dev = (key.device.major << 20) | (key.device.minor & 0xfffff);
                candidates.push((path.clone(), (dev, key.inode)));
            }
        }
        for provider in &self.watched {
            if path_basename(&provider.path).is_some_and(|base| base == name) {
                candidates.push((provider.path.clone(), (provider.dev, provider.ino)));
            }
        }
        candidates
    }

    /// Row B: the provider name test. A needed name matches a watched
    /// provider by SONAME when one is known, else by pinned-path
    /// basename. The test is pure names: no file is opened.
    fn matches_watched_provider(&self, name: &[u8]) -> bool {
        self.watched.iter().any(|provider| {
            if provider.soname.is_empty() {
                path_basename(&provider.path).is_some_and(|base| base == name)
            } else {
                provider.soname == name
            }
        })
    }

    /// Row B: resolve one needed name to an opened, identity-verified,
    /// parsed dependency. Returns `None` when no candidate survives,
    /// `Some(None)` when the name resolves to an already-parsed object
    /// (the edge is charged but no new object is), and `Some(Some)`
    /// with the fresh parse otherwise. Row D object accounting
    /// reserves against the remaining allowance *before* each new
    /// candidate is opened, failed attempts included (open failures,
    /// identity mismatches, failed parses, unstable brackets and
    /// SONAME mismatches all consume), so the 32-object ceiling is a
    /// bound on opened objects, never a post-parse discovery. When the
    /// allowance is spent, only an already-parsed candidate later in
    /// the order can still resolve the name. Each attempted candidate
    /// is opened, `fstat`-verified against its learned/pinned identity,
    /// stability-bracketed around its bounded parse, and SONAME-checked
    /// (a present SONAME must equal the needed name); the first candidate
    /// to survive all five wins, the rest are tried in deterministic order.
    /// A changed or unavailable intermediate voids that candidate, so its
    /// required chain resolves nowhere and the walk voids per Row C.
    /// A successful resolution records its dependency snapshot and the
    /// candidate count it chose from for later cache revalidation;
    /// any failed attempt marks the walk unclean (uncacheable), since a
    /// rejected candidate is not part of that recorded proof.
    fn resolve_needed(
        &self,
        name: &[u8],
        charge: &mut u64,
        visited: &mut BTreeSet<(u64, u64)>,
        capture_base: u64,
        proof: &mut WalkProof,
    ) -> Option<Option<ElfNeeded>> {
        let candidates = self.candidates_for(name);
        let candidate_count = candidates.len();
        for (path, identity) in candidates {
            if visited.contains(&identity) {
                // Already parsed this analysis: the name is resolved
                // and re-parsing would double-charge bytes.
                proof.resolutions.push((name.to_vec(), candidate_count));
                return Some(None);
            }
            if proof.objects >= HINT_MAX_OBJECTS_PER_ANALYSIS {
                // No allowance to open a new object; keep scanning
                // only in case an already-parsed candidate follows.
                continue;
            }
            proof.objects += 1;
            // FIFO-safe open (see analyze_executable): a plain open would
            // block on a writerless FIFO before identity could refuse it.
            let Ok(file) = open_regular(&path) else {
                proof.clean = false;
                continue;
            };
            let Ok(found) = identity_of(&file) else {
                proof.clean = false;
                continue;
            };
            if found != identity {
                // Path replaced since learning: not the file we knew.
                proof.clean = false;
                continue;
            }
            // Row A: bracket the bounded parse. A change or an
            // unavailable snapshot voids this candidate like any other
            // failed read; span charges already taken are never refunded.
            let pre = snapshot_of(&file).ok();
            #[cfg(test)]
            if let Some(mutate) = self.test_intermediate_mutator {
                mutate(&path);
            }
            let parsed = match read_elf_needed(&file, charge, capture_base) {
                Ok(parsed) => parsed,
                Err(_) => {
                    proof.clean = false;
                    continue;
                }
            };
            let (Some(pre), Ok(post)) = (pre, snapshot_of(&file)) else {
                proof.clean = false;
                continue;
            };
            if pre != post {
                proof.clean = false;
                continue;
            }
            if let Some(soname) = parsed.soname.as_deref()
                && soname != name
            {
                proof.clean = false;
                continue;
            }
            // Marked only after a successful parse: a failed candidate
            // must not shadow an intact alias with the same identity.
            visited.insert(identity);
            proof.deps.push(DepProof {
                dev: identity.0,
                ino: identity.1,
                size: pre.0,
                mtime_sec: pre.1,
                mtime_nsec: pre.2,
                ctime_sec: pre.3,
                ctime_nsec: pre.4,
            });
            proof.resolutions.push((name.to_vec(), candidate_count));
            return Some(Some(parsed));
        }
        None
    }

    /// Row D: the D-transitive walk. Each level first name-tests every
    /// edge (charging the edge budget): a provider match returns at
    /// once, a loader match latches. Untested levels never resolve, so a
    /// later sibling's provider witness survives an earlier sibling's
    /// unresolvable name. Then each name resolves: an unresolvable name,
    /// a blown object budget, or a blown capture budget voids to the
    /// latched loader hint if the loader chain completed within budget,
    /// else to `unknown`. A clean walk with no witness is honestly
    /// negative. Charges (objects reserved before each open, edges,
    /// bytes) include duplicates and failed parses and are never
    /// refunded. The returned proof records the dependency evidence
    /// behind the hint; only a clean proof may be cached, and a hit
    /// must revalidate it. Verdicts reached through the latched-loader
    /// fallback are never clean: their basis includes an unresolved or
    /// over-budget branch the proof does not record.
    fn walk_dependencies(&mut self, exe: &File, dev: u64, ino: u64) -> (StaticHint, WalkProof) {
        // Row D: every span read checks the remaining per-capture
        // allowance before touching the file, so the direct-provider
        // early return and the empty closure cannot over-read either.
        let capture_base = self.capture_bytes_charged;
        let mut charge = 0u64;
        let mut proof = WalkProof {
            objects: 1,
            deps: Vec::new(),
            resolutions: Vec::new(),
            clean: true,
        };
        let mut edges = 0usize;
        let mut visited = BTreeSet::from([(dev, ino)]);
        let exe_parsed = match read_elf_needed(exe, &mut charge, capture_base) {
            Ok(parsed) => parsed,
            Err(_) => {
                self.capture_bytes_charged = self.capture_bytes_charged.saturating_add(charge);
                proof.clean = false;
                return (StaticHint::Unknown, proof);
            }
        };
        let mut loader_latched = false;
        let mut level = vec![exe_parsed];
        for _depth in 0..HINT_MAX_DEPTH {
            let mut next = Vec::new();
            for parsed in &level {
                for name in &parsed.needed {
                    edges += 1;
                    if edges > HINT_MAX_EDGES_PER_ANALYSIS {
                        self.capture_bytes_charged =
                            self.capture_bytes_charged.saturating_add(charge);
                        proof.clean = false;
                        return (Self::latched_or_unknown(loader_latched), proof);
                    }
                    if self.matches_watched_provider(name) {
                        self.capture_bytes_charged =
                            self.capture_bytes_charged.saturating_add(charge);
                        return (StaticHint::LinksProvider, proof);
                    }
                    if name.as_slice() == HINT_LOADER_SONAME {
                        loader_latched = true;
                    }
                }
            }
            // Level name-tested with no provider witness: resolve every
            // edge. Resolution order is deterministic (level order, then
            // needed order); the first failure voids.
            for parsed in &level {
                for name in &parsed.needed {
                    let Some(resolved) = self.resolve_needed(
                        name,
                        &mut charge,
                        &mut visited,
                        capture_base,
                        &mut proof,
                    ) else {
                        self.capture_bytes_charged =
                            self.capture_bytes_charged.saturating_add(charge);
                        proof.clean = false;
                        return (Self::latched_or_unknown(loader_latched), proof);
                    };
                    let Some(resolved) = resolved else {
                        // Already parsed: the edge was charged, no new
                        // object followed.
                        continue;
                    };
                    if self.capture_bytes_charged.saturating_add(charge)
                        > HINT_MAX_BYTES_PER_CAPTURE
                    {
                        self.capture_bytes_charged =
                            self.capture_bytes_charged.saturating_add(charge);
                        proof.clean = false;
                        return (Self::latched_or_unknown(loader_latched), proof);
                    }
                    next.push(resolved);
                }
            }
            level = next;
        }
        self.capture_bytes_charged = self.capture_bytes_charged.saturating_add(charge);
        let hint = if loader_latched {
            StaticHint::LinksPkcs11Loader
        } else {
            StaticHint::NoStaticLinkWithinScope
        };
        (hint, proof)
    }

    fn latched_or_unknown(loader_latched: bool) -> StaticHint {
        if loader_latched {
            StaticHint::LinksPkcs11Loader
        } else {
            StaticHint::Unknown
        }
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

/// One bounded span read: bytes are charged before the read, so failed
/// parses still account for the spans they attempted, and no span can
/// over-allocate past the per-analysis budget. The remaining per-capture
/// allowance is checked before touching the file, so a starved analysis
/// refuses the span instead of over-reading past the capture cap.
struct BoundedReader<'a> {
    file: &'a File,
    charge: &'a mut u64,
    capture_base: u64,
}

impl BoundedReader<'_> {
    fn read_at(&mut self, offset: u64, len: usize) -> Result<Vec<u8>, ElfReadFailure> {
        *self.charge = self.charge.saturating_add(len as u64);
        if *self.charge > HINT_MAX_BYTES_PER_ANALYSIS {
            return Err(ElfReadFailure::OverBudget);
        }
        if self.capture_base.saturating_add(*self.charge) > HINT_MAX_BYTES_PER_CAPTURE {
            return Err(ElfReadFailure::OverBudget);
        }
        let mut buf = vec![0u8; len];
        self.file
            .read_exact_at(&mut buf, offset)
            .map_err(|_| ElfReadFailure::Malformed)?;
        Ok(buf)
    }
}

fn le_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn le_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Row B: read one object's `DT_NEEDED` names and optional `DT_SONAME`
/// through bounded spans (header, program headers, dynamic array,
/// string table). Every span is charged to the per-analysis budget,
/// including spans of failed parses, and refused before reading when it
/// would exceed the remaining per-capture allowance. Both 32- and 64-bit
/// little-endian objects parse; anything else — bad magic, big-endian,
/// truncated spans, an untranslatable string-table address, an
/// unterminated name — is `Malformed`. A name longer than 255 bytes is
/// `NameTooLong`. An object with no program headers or no `PT_DYNAMIC`
/// is honestly empty (statically linked as far as `DT_NEEDED` shows),
/// not malformed.
pub(crate) fn read_elf_needed(
    file: &File,
    charge: &mut u64,
    capture_base: u64,
) -> Result<ElfNeeded, ElfReadFailure> {
    let mut reader = BoundedReader {
        file,
        charge,
        capture_base,
    };
    let ehdr = reader.read_at(0, 64)?;
    if ehdr[0..4] != [0x7f, b'E', b'L', b'F'] {
        return Err(ElfReadFailure::Malformed);
    }
    let bits32 = match ehdr[4] {
        1 => true,
        2 => false,
        _ => return Err(ElfReadFailure::Malformed),
    };
    if ehdr[5] != 1 {
        return Err(ElfReadFailure::Malformed);
    }
    let (phoff, phentsize, phnum) = if bits32 {
        (
            u64::from(le_u32(&ehdr[0x1c..0x20])),
            usize::from(le_u16(&ehdr[0x2a..0x2c])),
            le_u16(&ehdr[0x2c..0x2e]),
        )
    } else {
        (
            le_u64(&ehdr[0x20..0x28]),
            usize::from(le_u16(&ehdr[0x36..0x38])),
            le_u16(&ehdr[0x38..0x3a]),
        )
    };
    if phnum == 0 {
        return Ok(ElfNeeded {
            needed: Vec::new(),
            soname: None,
        });
    }
    if phnum == 0xffff {
        return Err(ElfReadFailure::Malformed);
    }
    let min_entsize = if bits32 { 32 } else { 56 };
    if phentsize < min_entsize {
        return Err(ElfReadFailure::Malformed);
    }
    let phdrs = reader.read_at(phoff, usize::from(phnum) * phentsize)?;
    let mut loads: Vec<(u64, u64, u64)> = Vec::new();
    let mut dynamic: Option<(u64, u64)> = None;
    for index in 0..usize::from(phnum) {
        let base = index * phentsize;
        let p_type = le_u32(&phdrs[base..base + 4]);
        let (p_offset, p_vaddr, p_filesz) = if bits32 {
            (
                u64::from(le_u32(&phdrs[base + 4..base + 8])),
                u64::from(le_u32(&phdrs[base + 8..base + 12])),
                u64::from(le_u32(&phdrs[base + 16..base + 20])),
            )
        } else {
            (
                le_u64(&phdrs[base + 8..base + 16]),
                le_u64(&phdrs[base + 16..base + 24]),
                le_u64(&phdrs[base + 32..base + 40]),
            )
        };
        if p_type == 1 {
            loads.push((p_offset, p_vaddr, p_filesz));
        } else if p_type == 2 && dynamic.is_none() {
            dynamic = Some((p_offset, p_filesz));
        }
    }
    let Some((dyn_off, dyn_filesz)) = dynamic else {
        return Ok(ElfNeeded {
            needed: Vec::new(),
            soname: None,
        });
    };
    let entsize = if bits32 { 8u64 } else { 16u64 };
    if dyn_filesz % entsize != 0 {
        return Err(ElfReadFailure::Malformed);
    }
    let dyn_bytes = reader.read_at(dyn_off, dyn_filesz as usize)?;
    let mut needed_offs: Vec<u64> = Vec::new();
    let mut soname_off: Option<u64> = None;
    let mut strtab_vaddr: Option<u64> = None;
    let mut strsz: Option<u64> = None;
    for chunk in dyn_bytes.chunks_exact(entsize as usize) {
        let (tag, val) = if bits32 {
            (
                u64::from(le_u32(&chunk[0..4])),
                u64::from(le_u32(&chunk[4..8])),
            )
        } else {
            (le_u64(&chunk[0..8]), le_u64(&chunk[8..16]))
        };
        match tag {
            0 => break,
            1 => needed_offs.push(val),
            5 => strtab_vaddr = Some(val),
            10 => strsz = Some(val),
            14 => soname_off = soname_off.or(Some(val)),
            _ => {}
        }
    }
    if needed_offs.is_empty() && soname_off.is_none() {
        return Ok(ElfNeeded {
            needed: Vec::new(),
            soname: None,
        });
    }
    let (Some(strtab_vaddr), Some(strsz)) = (strtab_vaddr, strsz) else {
        return Err(ElfReadFailure::Malformed);
    };
    let containing = loads.iter().find(|(_, vaddr, filesz)| {
        strtab_vaddr
            .checked_sub(*vaddr)
            .is_some_and(|delta| delta < *filesz)
    });
    let Some((offset, vaddr, filesz)) = containing else {
        return Err(ElfReadFailure::Malformed);
    };
    // Checked translation: the file offset and the full DT_STRSZ span
    // must fit the containing load's file-backed range. Unchecked
    // arithmetic wrapped in release (misreading a translated span) and
    // panicked in debug; an overlong span over-read past the segment.
    // Refused before any strtab read or charge, like an untranslatable
    // address.
    let Some(delta) = strtab_vaddr.checked_sub(*vaddr) else {
        return Err(ElfReadFailure::Malformed);
    };
    let Some(strtab_off) = offset.checked_add(delta) else {
        return Err(ElfReadFailure::Malformed);
    };
    let (Some(strtab_end), Some(load_end)) =
        (strtab_off.checked_add(strsz), offset.checked_add(*filesz))
    else {
        return Err(ElfReadFailure::Malformed);
    };
    if strtab_end > load_end {
        return Err(ElfReadFailure::Malformed);
    }
    let strtab = reader.read_at(strtab_off, strsz as usize)?;
    let mut needed = Vec::with_capacity(needed_offs.len());
    for off in needed_offs {
        needed.push(extract_name(&strtab, off)?);
    }
    let soname = match soname_off {
        Some(off) => Some(extract_name(&strtab, off)?),
        None => None,
    };
    Ok(ElfNeeded { needed, soname })
}

/// Extract one NUL-terminated name at a string-table offset. Offsets past
/// the table and unterminated tails are malformed; names over 255 bytes
/// void the analysis on their own.
fn extract_name(strtab: &[u8], off: u64) -> Result<Vec<u8>, ElfReadFailure> {
    let off = off as usize;
    if off >= strtab.len() {
        return Err(ElfReadFailure::Malformed);
    }
    let tail = &strtab[off..];
    let end = tail.iter().position(|byte| *byte == 0);
    let Some(end) = end else {
        return Err(ElfReadFailure::Malformed);
    };
    if end > HINT_MAX_NEEDED_NAME_BYTES {
        return Err(ElfReadFailure::NameTooLong);
    }
    Ok(tail[..end].to_vec())
}

#[cfg(test)]
pub(crate) mod fixture {
    //! Hand-built minimal ELF fixtures with exact `DT_NEEDED`/`DT_SONAME`
    //! control. No toolchain dependency; every byte is asserted.
    //!
    //! (`MetadataExt` arrives via `super::*`; a second explicit import
    //! would be redundant.)

    use super::*;

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
        let file = std::fs::File::open(path).expect("open ELF fixture");
        super::identity_of(&file).expect("stat ELF fixture")
    }

    /// The scan-learned cache key for the file at `path`.
    pub(crate) fn cache_key_of(path: &Path) -> ObjectKey {
        let meta = std::fs::metadata(path).expect("stat ELF fixture");
        super::cache_key_of_metadata(&meta)
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::*;
    use super::*;

    fn watched(path: &Path, soname: &[u8]) -> WatchedProvider {
        let (dev, ino) = record_identity_of(path);
        WatchedProvider {
            path: path.to_path_buf(),
            soname: soname.to_vec(),
            dev,
            ino,
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
        state.set_enabled(true);
        // Disabled captures learn nothing (zero footprint when off).
        let mut off = ExtensiveState::new();
        let key = |inode| ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode,
        };
        off.learn_scan_path(key(7), Path::new("/z"));
        assert_eq!(off.path_cache_len_for_test(), 0);
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
        provider_spec.vaddr_bias = 0x0804_8000;
        let mut exe_spec = ElfSpec::exe(&[b"libprov.so.1"]);
        exe_spec.bits32 = true;
        exe_spec.vaddr_bias = 0x0804_8000;
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

    // P2-1 RED 1: changed-or-unavailable exe pre/post snapshot voids the
    // publication (Row A), inserting nothing. Stable twins keep proper
    // hints, including under a full verdict cache.
    #[test]
    fn elf_needed_changed_exe_snapshot_voids_publication() {
        fn append_byte(path: &Path) {
            use std::io::Write as _;
            let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
            file.write_all(&[0]).unwrap();
            file.sync_all().unwrap();
        }

        let dir = tempfile::tempdir().unwrap();
        let provider = write_elf(
            dir.path(),
            "libprov.so.1",
            &build_elf(&ElfSpec::lib(b"libprov.so.1", &[])),
        );
        let exe_stable = write_elf(
            dir.path(),
            "stable",
            &build_elf(&ElfSpec::exe(&[b"libprov.so.1"])),
        );
        let exe_changed = write_elf(
            dir.path(),
            "changed",
            &build_elf(&ElfSpec::exe(&[b"libprov.so.1"])),
        );
        let exe_unavail = write_elf(
            dir.path(),
            "unavail",
            &build_elf(&ElfSpec::exe(&[b"libprov.so.1"])),
        );

        let mut state = ExtensiveState::new();
        state.set_enabled(true);
        state.set_watched_for_test(vec![watched(&provider, b"libprov.so.1")]);
        for candidate in [&exe_stable, &exe_changed, &exe_unavail, &provider] {
            state.learn_scan_path(cache_key_of(candidate), candidate);
        }

        // Stable twin: proper hint, cached.
        let (sdev, sino) = record_identity_of(&exe_stable);
        assert_eq!(
            state.analyze_executable(sdev, sino),
            StaticHint::LinksProvider
        );
        assert_eq!(state.verdicts_len_for_test(), 1);

        // Changed mid-analysis (append between brackets): Unknown, no insert.
        state.test_exe_mutator = Some(append_byte);
        let (cdev, cino) = record_identity_of(&exe_changed);
        assert_eq!(state.analyze_executable(cdev, cino), StaticHint::Unknown);
        assert_eq!(
            state.verdicts_len_for_test(),
            1,
            "changed exe must not insert"
        );

        // Unavailable post snapshot: Unknown, no insert.
        state.test_exe_mutator = None;
        state.test_fail_exe_post_snapshot = true;
        let (udev, uino) = record_identity_of(&exe_unavail);
        assert_eq!(state.analyze_executable(udev, uino), StaticHint::Unknown);
        assert_eq!(state.verdicts_len_for_test(), 1);
        state.test_fail_exe_post_snapshot = false;

        // Unavailable pre snapshot: Unknown, no insert.
        state.test_fail_exe_pre_snapshot = true;
        let exe_pre = write_elf(
            dir.path(),
            "pre",
            &build_elf(&ElfSpec::exe(&[b"libprov.so.1"])),
        );
        state.learn_scan_path(cache_key_of(&exe_pre), &exe_pre);
        let (pdev, pino) = record_identity_of(&exe_pre);
        assert_eq!(state.analyze_executable(pdev, pino), StaticHint::Unknown);
        assert_eq!(state.verdicts_len_for_test(), 1);
        state.test_fail_exe_pre_snapshot = false;

        // Stable twin still hints after the failures (cache hit).
        assert_eq!(
            state.analyze_executable(sdev, sino),
            StaticHint::LinksProvider
        );
        assert_eq!(state.analyses_run_for_test(), 4);

        // Full verdict cache neighbor: hits serve, new verdicts retain nothing.
        let mut full = ExtensiveState::new();
        full.set_enabled(true);
        full.set_watched_for_test(vec![watched(&provider, b"libprov.so.1")]);
        full.learn_scan_path(cache_key_of(&exe_stable), &exe_stable);
        full.learn_scan_path(cache_key_of(&provider), &provider);
        let (fdev, fino) = record_identity_of(&exe_stable);
        assert_eq!(
            full.analyze_executable(fdev, fino),
            StaticHint::LinksProvider
        );
        for index in 0..HINT_MAX_VERDICT_CACHE_ENTRIES - 1 {
            let key = (
                0xffff_ffff_0000_0000u64 + index as u64,
                0xffff_ffff_0000_0000u64 + index as u64,
            );
            full.verdicts.insert(
                key,
                VerdictEntry {
                    hint: StaticHint::NoStaticLinkWithinScope,
                    size: 0,
                    mtime_sec: 0,
                    mtime_nsec: 0,
                    ctime_sec: 0,
                    ctime_nsec: 0,
                    deps: Vec::new(),
                    resolutions: Vec::new(),
                    watched_names: Vec::new(),
                },
            );
        }
        assert_eq!(full.verdicts_len_for_test(), HINT_MAX_VERDICT_CACHE_ENTRIES);
        assert_eq!(
            full.analyze_executable(fdev, fino),
            StaticHint::LinksProvider
        );
        assert_eq!(full.analyses_run_for_test(), 1);
        let exe_new = write_elf(
            dir.path(),
            "newstable",
            &build_elf(&ElfSpec::exe(&[b"libprov.so.1"])),
        );
        full.learn_scan_path(cache_key_of(&exe_new), &exe_new);
        let (ndev, nino) = record_identity_of(&exe_new);
        assert_eq!(
            full.analyze_executable(ndev, nino),
            StaticHint::LinksProvider
        );
        assert_eq!(full.verdicts_len_for_test(), HINT_MAX_VERDICT_CACHE_ENTRIES);
        assert_eq!(full.analyses_run_for_test(), 2);
    }

    // P2-1 RED 2: a changed intermediate dependency voids its required
    // chain to Unknown. A direct-provider chain that avoids the changed
    // object still links.
    #[test]
    fn elf_needed_changed_intermediate_voids_required_chain() {
        fn append_if_helper(path: &Path) {
            if path
                .file_name()
                .is_some_and(|name| name == "libhelper.so.1")
            {
                use std::io::Write as _;
                let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
                file.write_all(&[0]).unwrap();
                file.sync_all().unwrap();
            }
        }

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
        let exe_direct = write_elf(
            dir.path(),
            "direct",
            &build_elf(&ElfSpec::exe(&[b"libprov.so.1"])),
        );

        let mut stable = ExtensiveState::new();
        stable.set_enabled(true);
        stable.set_watched_for_test(vec![watched(&provider, b"libprov.so.1")]);
        for candidate in [&exe, &helper, &provider, &exe_direct] {
            stable.learn_scan_path(cache_key_of(candidate), candidate);
        }
        let (edev, eino) = record_identity_of(&exe);
        assert_eq!(
            stable.analyze_executable(edev, eino),
            StaticHint::LinksProvider
        );

        let mut changed = ExtensiveState::new();
        changed.set_enabled(true);
        changed.set_watched_for_test(vec![watched(&provider, b"libprov.so.1")]);
        for candidate in [&exe, &helper, &provider, &exe_direct] {
            changed.learn_scan_path(cache_key_of(candidate), candidate);
        }
        changed.test_intermediate_mutator = Some(append_if_helper);
        assert_eq!(changed.analyze_executable(edev, eino), StaticHint::Unknown);
        assert_eq!(changed.verdicts_len_for_test(), 0);

        // Neighbor: the direct chain avoids the changed helper.
        let (ddev, dino) = record_identity_of(&exe_direct);
        assert_eq!(
            changed.analyze_executable(ddev, dino),
            StaticHint::LinksProvider
        );
        assert_eq!(changed.verdicts_len_for_test(), 1);
    }

    // P2-1 RED 3: remaining capture allowance below the first required
    // span refuses before the excess read. Exact-bound twins succeed;
    // failed and duplicate work still charges; earlier verdicts survive.
    #[test]
    fn elf_needed_capture_budget_checked_before_span_reads() {
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

        let mut measure = ExtensiveState::new();
        measure.set_enabled(true);
        measure.set_watched_for_test(vec![watched(&provider, b"libprov.so.1")]);
        for candidate in [&exe, &helper, &provider] {
            measure.learn_scan_path(cache_key_of(candidate), candidate);
        }
        let (edev, eino) = record_identity_of(&exe);
        assert_eq!(
            measure.analyze_executable(edev, eino),
            StaticHint::LinksProvider
        );
        let total = measure.capture_bytes_charged_for_test();
        assert!(total > 64, "fixture too small to test span gating");

        // Just below the 64-byte header span: Unknown, refused span
        // charged once, nothing cached.
        let mut starved = ExtensiveState::new();
        starved.set_enabled(true);
        starved.set_watched_for_test(vec![watched(&provider, b"libprov.so.1")]);
        for candidate in [&exe, &helper, &provider] {
            starved.learn_scan_path(cache_key_of(candidate), candidate);
        }
        starved.capture_bytes_charged = HINT_MAX_BYTES_PER_CAPTURE - 63;
        let before = starved.capture_bytes_charged_for_test();
        assert_eq!(starved.analyze_executable(edev, eino), StaticHint::Unknown);
        assert_eq!(
            starved.capture_bytes_charged_for_test(),
            before + 64,
            "refused span charged once, no excess read"
        );
        assert_eq!(starved.verdicts_len_for_test(), 0);
        assert_eq!(starved.analyses_run_for_test(), 1);

        // Exact-bound twin: remaining equals the measured total.
        let mut exact = ExtensiveState::new();
        exact.set_enabled(true);
        exact.set_watched_for_test(vec![watched(&provider, b"libprov.so.1")]);
        for candidate in [&exe, &helper, &provider] {
            exact.learn_scan_path(cache_key_of(candidate), candidate);
        }
        exact.capture_bytes_charged = HINT_MAX_BYTES_PER_CAPTURE - total;
        assert_eq!(
            exact.analyze_executable(edev, eino),
            StaticHint::LinksProvider
        );
        assert_eq!(
            exact.capture_bytes_charged_for_test(),
            HINT_MAX_BYTES_PER_CAPTURE
        );
        assert_eq!(exact.verdicts_len_for_test(), 1);

        // Failed work charges; duplicate re-attempts charge again.
        let mut truncated = build_elf(&ElfSpec::exe(&[b"libprov.so.1"]));
        truncated.truncate(truncated.len() / 2);
        let exe_trunc = write_elf(dir.path(), "trunc", &truncated);
        let mut failed = ExtensiveState::new();
        failed.set_enabled(true);
        failed.set_watched_for_test(vec![watched(&provider, b"libprov.so.1")]);
        failed.learn_scan_path(cache_key_of(&exe_trunc), &exe_trunc);
        failed.learn_scan_path(cache_key_of(&provider), &provider);
        let (tdev, tino) = record_identity_of(&exe_trunc);
        let before_fail = failed.capture_bytes_charged_for_test();
        assert_eq!(failed.analyze_executable(tdev, tino), StaticHint::Unknown);
        let after_first = failed.capture_bytes_charged_for_test();
        assert!(after_first > before_fail, "failed parse must charge");
        assert_eq!(failed.verdicts_len_for_test(), 0);
        assert_eq!(failed.analyze_executable(tdev, tino), StaticHint::Unknown);
        assert!(
            failed.capture_bytes_charged_for_test() > after_first,
            "duplicate failed work must charge again"
        );
        assert_eq!(failed.analyses_run_for_test(), 2);

        // Earlier complete verdicts survive a later starved refusal.
        let exe_direct = write_elf(
            dir.path(),
            "direct",
            &build_elf(&ElfSpec::exe(&[b"libprov.so.1"])),
        );
        let mut preserve = ExtensiveState::new();
        preserve.set_enabled(true);
        preserve.set_watched_for_test(vec![watched(&provider, b"libprov.so.1")]);
        for candidate in [&exe, &helper, &provider, &exe_direct] {
            preserve.learn_scan_path(cache_key_of(candidate), candidate);
        }
        let (ddev, dino) = record_identity_of(&exe_direct);
        assert_eq!(
            preserve.analyze_executable(ddev, dino),
            StaticHint::LinksProvider
        );
        assert_eq!(preserve.verdicts_len_for_test(), 1);
        preserve.capture_bytes_charged = HINT_MAX_BYTES_PER_CAPTURE - 63;
        assert_eq!(preserve.analyze_executable(edev, eino), StaticHint::Unknown);
        assert!(
            preserve.verdicts.contains_key(&(ddev, dino)),
            "earlier verdict preserved"
        );
    }

    // P2-1 RED 4: the direct-provider early return and the empty or
    // no-provider closure obey the same per-span capture cap. Cache
    // hits need no reads; revalidation and late-unrelated-failure
    // witnesses keep their standing.
    #[test]
    fn elf_needed_capture_budget_gates_provider_and_empty_closure() {
        let dir = tempfile::tempdir().unwrap();
        let provider = write_elf(
            dir.path(),
            "libprov.so.1",
            &build_elf(&ElfSpec::lib(b"libprov.so.1", &[])),
        );
        let exe_direct = write_elf(
            dir.path(),
            "direct",
            &build_elf(&ElfSpec::exe(&[b"libprov.so.1"])),
        );
        let exe_empty = write_elf(dir.path(), "empty", &build_elf(&ElfSpec::exe(&[])));

        let mut measure_direct = ExtensiveState::new();
        measure_direct.set_enabled(true);
        measure_direct.set_watched_for_test(vec![watched(&provider, b"libprov.so.1")]);
        measure_direct.learn_scan_path(cache_key_of(&exe_direct), &exe_direct);
        measure_direct.learn_scan_path(cache_key_of(&provider), &provider);
        let (ddev, dino) = record_identity_of(&exe_direct);
        assert_eq!(
            measure_direct.analyze_executable(ddev, dino),
            StaticHint::LinksProvider
        );
        let total_direct = measure_direct.capture_bytes_charged_for_test();

        let mut measure_empty = ExtensiveState::new();
        measure_empty.set_enabled(true);
        measure_empty.learn_scan_path(cache_key_of(&exe_empty), &exe_empty);
        let (edev, eino) = record_identity_of(&exe_empty);
        assert_eq!(
            measure_empty.analyze_executable(edev, eino),
            StaticHint::NoStaticLinkWithinScope
        );
        let total_empty = measure_empty.capture_bytes_charged_for_test();

        // Starved direct-provider early return: Unknown, no excess read.
        let mut starved_direct = ExtensiveState::new();
        starved_direct.set_enabled(true);
        starved_direct.set_watched_for_test(vec![watched(&provider, b"libprov.so.1")]);
        starved_direct.learn_scan_path(cache_key_of(&exe_direct), &exe_direct);
        starved_direct.learn_scan_path(cache_key_of(&provider), &provider);
        starved_direct.capture_bytes_charged = HINT_MAX_BYTES_PER_CAPTURE - 63;
        let before_direct = starved_direct.capture_bytes_charged_for_test();
        assert_eq!(
            starved_direct.analyze_executable(ddev, dino),
            StaticHint::Unknown
        );
        assert_eq!(
            starved_direct.capture_bytes_charged_for_test(),
            before_direct + 64,
            "direct early return must not over-read"
        );

        // Starved empty closure: Unknown, no excess read.
        let mut starved_empty = ExtensiveState::new();
        starved_empty.set_enabled(true);
        starved_empty.learn_scan_path(cache_key_of(&exe_empty), &exe_empty);
        starved_empty.capture_bytes_charged = HINT_MAX_BYTES_PER_CAPTURE - 63;
        let before_empty = starved_empty.capture_bytes_charged_for_test();
        assert_eq!(
            starved_empty.analyze_executable(edev, eino),
            StaticHint::Unknown
        );
        assert_eq!(
            starved_empty.capture_bytes_charged_for_test(),
            before_empty + 64,
            "empty closure must not over-read"
        );

        // Exact-bound twins hit the limit precisely and keep their hints.
        let mut exact_direct = ExtensiveState::new();
        exact_direct.set_enabled(true);
        exact_direct.set_watched_for_test(vec![watched(&provider, b"libprov.so.1")]);
        exact_direct.learn_scan_path(cache_key_of(&exe_direct), &exe_direct);
        exact_direct.learn_scan_path(cache_key_of(&provider), &provider);
        exact_direct.capture_bytes_charged = HINT_MAX_BYTES_PER_CAPTURE - total_direct;
        assert_eq!(
            exact_direct.analyze_executable(ddev, dino),
            StaticHint::LinksProvider
        );
        assert_eq!(
            exact_direct.capture_bytes_charged_for_test(),
            HINT_MAX_BYTES_PER_CAPTURE
        );

        let mut exact_empty = ExtensiveState::new();
        exact_empty.set_enabled(true);
        exact_empty.learn_scan_path(cache_key_of(&exe_empty), &exe_empty);
        exact_empty.capture_bytes_charged = HINT_MAX_BYTES_PER_CAPTURE - total_empty;
        assert_eq!(
            exact_empty.analyze_executable(edev, eino),
            StaticHint::NoStaticLinkWithinScope
        );
        assert_eq!(
            exact_empty.capture_bytes_charged_for_test(),
            HINT_MAX_BYTES_PER_CAPTURE
        );

        // Cache hit with low remaining needs no reads and still serves.
        let mut cached = ExtensiveState::new();
        cached.set_enabled(true);
        cached.set_watched_for_test(vec![watched(&provider, b"libprov.so.1")]);
        cached.learn_scan_path(cache_key_of(&exe_direct), &exe_direct);
        cached.learn_scan_path(cache_key_of(&provider), &provider);
        assert_eq!(
            cached.analyze_executable(ddev, dino),
            StaticHint::LinksProvider
        );
        cached.capture_bytes_charged = HINT_MAX_BYTES_PER_CAPTURE - 63;
        assert_eq!(
            cached.analyze_executable(ddev, dino),
            StaticHint::LinksProvider,
            "cache hit needs no reads"
        );
        assert_eq!(cached.analyses_run_for_test(), 1);
        assert_eq!(
            cached.capture_bytes_charged_for_test(),
            HINT_MAX_BYTES_PER_CAPTURE - 63
        );

        // Revalidation neighbor: same inode, new bytes refuse the stale hit.
        let mut reval = ExtensiveState::new();
        reval.set_enabled(true);
        reval.learn_scan_path(cache_key_of(&exe_empty), &exe_empty);
        assert_eq!(
            reval.analyze_executable(edev, eino),
            StaticHint::NoStaticLinkWithinScope
        );
        std::fs::write(&exe_empty, build_elf(&ElfSpec::exe(&[]))).unwrap();
        assert_eq!(
            reval.analyze_executable(edev, eino),
            StaticHint::NoStaticLinkWithinScope
        );
        assert_eq!(reval.analyses_run_for_test(), 2);

        // Late-unrelated-failure neighbors keep their witnesses.
        let exe_loader_mixed = write_elf(
            dir.path(),
            "loadermix",
            &build_elf(&ElfSpec::exe(&[b"libp11-kit.so.0", b"libmissing.so.9"])),
        );
        let exe_provider_mixed = write_elf(
            dir.path(),
            "provmix",
            &build_elf(&ElfSpec::exe(&[b"libprov.so.1", b"libmissing.so.9"])),
        );
        let mut late = ExtensiveState::new();
        late.set_enabled(true);
        late.set_watched_for_test(vec![watched(&provider, b"libprov.so.1")]);
        late.learn_scan_path(cache_key_of(&exe_loader_mixed), &exe_loader_mixed);
        late.learn_scan_path(cache_key_of(&exe_provider_mixed), &exe_provider_mixed);
        late.learn_scan_path(cache_key_of(&provider), &provider);
        let (ldev, lino) = record_identity_of(&exe_loader_mixed);
        assert_eq!(
            late.analyze_executable(ldev, lino),
            StaticHint::LinksPkcs11Loader
        );
        let (pdev, pino) = record_identity_of(&exe_provider_mixed);
        assert_eq!(
            late.analyze_executable(pdev, pino),
            StaticHint::LinksProvider
        );
    }

    // 614b P2#3: the 32-object budget reserves each new candidate
    // before it is opened, so object 33 is never examined. The padded
    // 33rd object makes any actual span read visible in the capture
    // byte charge: the learned twin must charge exactly what the
    // unlearned twin charges.
    #[test]
    fn elf_needed_object_attempts_stop_before_33() {
        let dir = tempfile::tempdir().unwrap();
        let mut names: Vec<Vec<u8>> = Vec::new();
        let mut libs: Vec<PathBuf> = Vec::new();
        for index in 0..32 {
            let name = format!("libo{index:02}.so").into_bytes();
            let mut spec = ElfSpec::lib(&name, &[]);
            if index == 31 {
                spec.strtab_pad = 64 * 1024;
            }
            let lib = write_elf(dir.path(), &format!("libo{index:02}.so"), &build_elf(&spec));
            names.push(name);
            libs.push(lib);
        }
        // At-cap positive control: executable + 31 dependencies is
        // exactly 32 objects and completes.
        let refs31: Vec<&[u8]> = names[..31].iter().map(Vec::as_slice).collect();
        let exe31 = write_elf(dir.path(), "atcap", &build_elf(&ElfSpec::exe(&refs31)));
        let lib_refs31: Vec<&Path> = libs[..31].iter().map(PathBuf::as_path).collect();
        let (hint, _) = analyzed(dir.path(), vec![], &exe31, &lib_refs31);
        assert_eq!(hint, StaticHint::NoStaticLinkWithinScope);

        let refs: Vec<&[u8]> = names.iter().map(Vec::as_slice).collect();
        let exe = write_elf(dir.path(), "overcap", &build_elf(&ElfSpec::exe(&refs)));
        let lib_refs: Vec<&Path> = libs.iter().map(PathBuf::as_path).collect();
        let (hint_learned, learned) = analyzed(dir.path(), vec![], &exe, &lib_refs);
        let (hint_unlearned, unlearned) = analyzed(dir.path(), vec![], &exe, &lib_refs31);
        assert_eq!(hint_learned, StaticHint::Unknown);
        assert_eq!(hint_unlearned, StaticHint::Unknown);
        assert_eq!(
            learned.capture_bytes_charged_for_test(),
            unlearned.capture_bytes_charged_for_test(),
            "object 33 must be refused before any of its spans are read"
        );
    }

    // 614b P2#3: failed candidates (SONAME-mismatched or malformed)
    // consume the same pre-open object budget, so a matching
    // candidate ordered after the budget is never opened. Candidate
    // order is path-cache key order; the matching body is written
    // into whichever file sorts last.
    #[test]
    fn elf_needed_failed_candidates_consume_object_budget() {
        fn scenario(
            dir: &Path,
            base: &str,
            count: usize,
            malformed: bool,
        ) -> (PathBuf, Vec<PathBuf>) {
            let mut paths = Vec::new();
            for index in 0..count {
                let sub = dir.join(format!("{base}-{index}"));
                std::fs::create_dir(&sub).unwrap();
                paths.push(write_elf(&sub, base, &[0u8; 8]));
            }
            let mut ordered: Vec<(ObjectKey, PathBuf)> = paths
                .iter()
                .map(|path| (cache_key_of(path), path.clone()))
                .collect();
            ordered.sort();
            let bad_body = if malformed {
                vec![0u8; 128]
            } else {
                build_elf(&ElfSpec::lib(b"libother.so", &[]))
            };
            let good_body = build_elf(&ElfSpec::lib(base.as_bytes(), &[]));
            for (pos, (_, path)) in ordered.iter().enumerate() {
                let body = if pos + 1 == count {
                    &good_body
                } else {
                    &bad_body
                };
                std::fs::write(path, body).unwrap();
            }
            let exe = write_elf(
                dir,
                &format!("exe-{base}"),
                &build_elf(&ElfSpec::exe(&[base.as_bytes()])),
            );
            (exe, paths)
        }

        let dir = tempfile::tempdir().unwrap();
        for malformed in [false, true] {
            let base = if malformed { "liby.so" } else { "libx.so" };
            let (exe, libs) = scenario(dir.path(), base, 40, malformed);
            let refs: Vec<&Path> = libs.iter().map(PathBuf::as_path).collect();
            let (hint, state) = analyzed(dir.path(), vec![], &exe, &refs);
            assert_eq!(
                hint,
                StaticHint::Unknown,
                "malformed={malformed}: failed candidates must exhaust the \
                 object budget before the matching candidate is opened"
            );
            assert_eq!(state.analyses_run_for_test(), 1);
        }
        // Below-cap twin: a handful of failed candidates still
        // reaches the matching one and completes the negative.
        let (exe, libs) = scenario(dir.path(), "libz.so", 6, false);
        let refs: Vec<&Path> = libs.iter().map(PathBuf::as_path).collect();
        let (hint, _) = analyzed(dir.path(), vec![], &exe, &refs);
        assert_eq!(hint, StaticHint::NoStaticLinkWithinScope);
    }

    fn transitive_state(provider: &Path, exe: &Path, helper: &Path) -> ExtensiveState {
        let mut state = ExtensiveState::new();
        state.set_enabled(true);
        state.set_watched_for_test(vec![watched(provider, b"libprov.so.1")]);
        for candidate in [exe, helper, provider] {
            state.learn_scan_path(cache_key_of(candidate), candidate);
        }
        state
    }

    // 614b P2#4: a transitive cache hit must revalidate the
    // intermediate dependency evidence, not just the executable. An
    // unchanged helper still serves the hit; an overwritten helper
    // (same inode, now needing the provider) refuses it.
    #[test]
    fn elf_needed_transitive_cache_revalidates_changed_helper() {
        let dir = tempfile::tempdir().unwrap();
        let provider = write_elf(
            dir.path(),
            "libprov.so.1",
            &build_elf(&ElfSpec::lib(b"libprov.so.1", &[])),
        );
        let helper = write_elf(
            dir.path(),
            "libhelper.so.1",
            &build_elf(&ElfSpec::lib(b"libhelper.so.1", &[])),
        );
        let exe = write_elf(
            dir.path(),
            "exe",
            &build_elf(&ElfSpec::exe(&[b"libhelper.so.1"])),
        );
        let mut state = transitive_state(&provider, &exe, &helper);
        let (dev, ino) = record_identity_of(&exe);
        assert_eq!(
            state.analyze_executable(dev, ino),
            StaticHint::NoStaticLinkWithinScope
        );
        // Stable helper: the hit serves without re-analysis.
        assert_eq!(
            state.analyze_executable(dev, ino),
            StaticHint::NoStaticLinkWithinScope
        );
        assert_eq!(state.analyses_run_for_test(), 1);
        // Same helper inode, SONAME preserved, now needing the
        // provider: the cached negative must not survive.
        std::fs::write(
            &helper,
            build_elf(&ElfSpec::lib(b"libhelper.so.1", &[b"libprov.so.1"])),
        )
        .unwrap();
        assert_eq!(
            state.analyze_executable(dev, ino),
            StaticHint::LinksProvider,
            "changed helper must refuse the cached transitive negative"
        );
        assert_eq!(state.analyses_run_for_test(), 2);
        let mut fresh = transitive_state(&provider, &exe, &helper);
        assert_eq!(
            fresh.analyze_executable(dev, ino),
            StaticHint::LinksProvider
        );
    }

    // 614b P2#4: a removed helper voids a cached completed hint to
    // unknown, and a helper replaced from provider-needing to empty
    // turns a cached positive into a fresh negative.
    #[test]
    fn elf_needed_transitive_cache_refuses_removed_or_replaced_helper() {
        let dir = tempfile::tempdir().unwrap();
        let provider = write_elf(
            dir.path(),
            "libprov.so.1",
            &build_elf(&ElfSpec::lib(b"libprov.so.1", &[])),
        );
        let helper = write_elf(
            dir.path(),
            "libhelper.so.1",
            &build_elf(&ElfSpec::lib(b"libhelper.so.1", &[])),
        );
        let exe = write_elf(
            dir.path(),
            "exe",
            &build_elf(&ElfSpec::exe(&[b"libhelper.so.1"])),
        );
        let mut removed = transitive_state(&provider, &exe, &helper);
        let (dev, ino) = record_identity_of(&exe);
        assert_eq!(
            removed.analyze_executable(dev, ino),
            StaticHint::NoStaticLinkWithinScope
        );
        std::fs::remove_file(&helper).unwrap();
        assert_eq!(
            removed.analyze_executable(dev, ino),
            StaticHint::Unknown,
            "removed helper must refuse the cached transitive negative"
        );
        assert_eq!(removed.analyses_run_for_test(), 2);

        // Positive-to-negative: the helper first needs the provider,
        // then is overwritten empty at the same inode.
        std::fs::write(
            &helper,
            build_elf(&ElfSpec::lib(b"libhelper.so.1", &[b"libprov.so.1"])),
        )
        .unwrap();
        let mut replaced = transitive_state(&provider, &exe, &helper);
        assert_eq!(
            replaced.analyze_executable(dev, ino),
            StaticHint::LinksProvider
        );
        assert_eq!(
            replaced.analyze_executable(dev, ino),
            StaticHint::LinksProvider
        );
        assert_eq!(replaced.analyses_run_for_test(), 1);
        std::fs::write(&helper, build_elf(&ElfSpec::lib(b"libhelper.so.1", &[]))).unwrap();
        assert_eq!(
            replaced.analyze_executable(dev, ino),
            StaticHint::NoStaticLinkWithinScope,
            "replaced helper must refuse the cached transitive positive"
        );
        assert_eq!(replaced.analyses_run_for_test(), 2);
    }

    // 614b round-2 P2#1: a learned path replaced with a writerless FIFO
    // must refuse promptly (Unknown) instead of blocking in open. The
    // adverse analysis runs in an owned child with a bounded wait: the
    // parent kills a blocked child and fails, so RED never hangs the
    // suite. Cold/cached x executable/intermediate.
    const FIFO_CHILD_MARKER: &str = "P11SCOPE_614B_FIFO_CHILD";
    const FIFO_CHILD_DIR: &str = "P11SCOPE_614B_FIFO_DIR";
    const FIFO_CHILD_TIMEOUT_SECS: u64 = 15;

    fn replace_with_fifo(path: &Path) {
        use std::os::unix::fs::FileTypeExt as _;
        std::fs::remove_file(path).unwrap();
        let raw = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: NUL-free path, mode bits only.
        let rc = unsafe { libc::mkfifo(raw.as_ptr(), 0o644) };
        assert_eq!(rc, 0, "mkfifo {}", path.display());
        assert!(
            std::fs::symlink_metadata(path)
                .unwrap()
                .file_type()
                .is_fifo()
        );
    }

    /// Parent side: respawn this same test in an owned child with a
    /// bounded wait; child side: run `child` in the parent-owned dir.
    /// A blocked child is killed and fails the test instead of hanging
    /// it. The `1 passed` plus marker assertions keep a misnamed
    /// `--exact` selector (zero tests run) from passing vacuously.
    fn fifo_child_or_spawn(test_name: &str, case: &str, child: fn(&Path)) {
        use std::process::{Command, Stdio};
        if std::env::var_os(FIFO_CHILD_MARKER).is_some() {
            let dir = std::env::var_os(FIFO_CHILD_DIR).expect("fifo child dir");
            child(Path::new(&dir));
            println!("FIFO-CASE {case} DONE");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let mut spawned = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(format!("discovery::elf_needed::tests::{test_name}"))
            .arg("--nocapture")
            .env(FIFO_CHILD_MARKER, "1")
            .env(FIFO_CHILD_DIR, dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(FIFO_CHILD_TIMEOUT_SECS);
        loop {
            match spawned.try_wait().unwrap() {
                Some(status) => {
                    let mut stdout = String::new();
                    use std::io::Read as _;
                    spawned
                        .stdout
                        .take()
                        .unwrap()
                        .read_to_string(&mut stdout)
                        .unwrap();
                    assert!(
                        status.success()
                            && stdout.contains("1 passed")
                            && stdout.contains(&format!("FIFO-CASE {case} DONE")),
                        "fifo case {case} child failed: status={status} stdout={stdout:?}"
                    );
                    return;
                }
                None => {
                    if std::time::Instant::now() >= deadline {
                        let _ = spawned.kill();
                        let _ = spawned.wait();
                        panic!(
                            "fifo case {case} blocked: a replaced-path open must refuse a \
                             writerless FIFO promptly"
                        );
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        }
    }

    fn fifo_case_exe_cold(dir: &Path) {
        let provider = write_elf(
            dir,
            "libprov.so.1",
            &build_elf(&ElfSpec::lib(b"libprov.so.1", &[])),
        );
        let exe = write_elf(dir, "exe", &build_elf(&ElfSpec::exe(&[b"libprov.so.1"])));
        let mut state = ExtensiveState::new();
        state.set_enabled(true);
        state.set_watched_for_test(vec![watched(&provider, b"libprov.so.1")]);
        state.learn_scan_path(cache_key_of(&exe), &exe);
        state.learn_scan_path(cache_key_of(&provider), &provider);
        let (dev, ino) = record_identity_of(&exe);
        replace_with_fifo(&exe);
        assert_eq!(state.analyze_executable(dev, ino), StaticHint::Unknown);
        assert_eq!(
            state.capture_bytes_charged_for_test(),
            0,
            "fifo exe must be refused before any ELF read"
        );
        assert_eq!(state.verdicts_len_for_test(), 0);
        assert_eq!(state.analyses_run_for_test(), 1);
    }

    fn fifo_case_exe_cached(dir: &Path) {
        let provider = write_elf(
            dir,
            "libprov.so.1",
            &build_elf(&ElfSpec::lib(b"libprov.so.1", &[])),
        );
        let exe = write_elf(dir, "exe", &build_elf(&ElfSpec::exe(&[b"libprov.so.1"])));
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
        let charged = state.capture_bytes_charged_for_test();
        assert!(charged > 0);
        assert_eq!(state.verdicts_len_for_test(), 1);
        replace_with_fifo(&exe);
        assert_eq!(state.analyze_executable(dev, ino), StaticHint::Unknown);
        assert_eq!(
            state.capture_bytes_charged_for_test(),
            charged,
            "cached fifo exe must be refused before any ELF read"
        );
        assert_eq!(state.verdicts_len_for_test(), 0, "stale verdict dropped");
        assert_eq!(state.analyses_run_for_test(), 2);
    }

    fn fifo_case_helper_cold(dir: &Path) {
        let provider = write_elf(
            dir,
            "libprov.so.1",
            &build_elf(&ElfSpec::lib(b"libprov.so.1", &[])),
        );
        let helper = write_elf(
            dir,
            "libhelper.so.1",
            &build_elf(&ElfSpec::lib(b"libhelper.so.1", &[b"libprov.so.1"])),
        );
        let exe = write_elf(dir, "exe", &build_elf(&ElfSpec::exe(&[b"libhelper.so.1"])));
        // Unlearned-helper twin: the same shape with the helper never
        // learned, so the refusal reads only the executable.
        let mut twin = ExtensiveState::new();
        twin.set_enabled(true);
        twin.set_watched_for_test(vec![watched(&provider, b"libprov.so.1")]);
        twin.learn_scan_path(cache_key_of(&exe), &exe);
        twin.learn_scan_path(cache_key_of(&provider), &provider);
        let (dev, ino) = record_identity_of(&exe);
        assert_eq!(twin.analyze_executable(dev, ino), StaticHint::Unknown);
        let twin_charged = twin.capture_bytes_charged_for_test();

        let mut state = ExtensiveState::new();
        state.set_enabled(true);
        state.set_watched_for_test(vec![watched(&provider, b"libprov.so.1")]);
        state.learn_scan_path(cache_key_of(&exe), &exe);
        state.learn_scan_path(cache_key_of(&helper), &helper);
        state.learn_scan_path(cache_key_of(&provider), &provider);
        replace_with_fifo(&helper);
        assert_eq!(state.analyze_executable(dev, ino), StaticHint::Unknown);
        assert_eq!(
            state.capture_bytes_charged_for_test(),
            twin_charged,
            "fifo helper must be refused before any of its spans are read"
        );
        assert_eq!(state.verdicts_len_for_test(), 0);
        assert_eq!(state.analyses_run_for_test(), 1);
    }

    fn fifo_case_helper_cached(dir: &Path) {
        let provider = write_elf(
            dir,
            "libprov.so.1",
            &build_elf(&ElfSpec::lib(b"libprov.so.1", &[])),
        );
        let helper = write_elf(
            dir,
            "libhelper.so.1",
            &build_elf(&ElfSpec::lib(b"libhelper.so.1", &[b"libprov.so.1"])),
        );
        let exe = write_elf(dir, "exe", &build_elf(&ElfSpec::exe(&[b"libhelper.so.1"])));
        let mut state = ExtensiveState::new();
        state.set_enabled(true);
        state.set_watched_for_test(vec![watched(&provider, b"libprov.so.1")]);
        state.learn_scan_path(cache_key_of(&exe), &exe);
        state.learn_scan_path(cache_key_of(&helper), &helper);
        state.learn_scan_path(cache_key_of(&provider), &provider);
        let (dev, ino) = record_identity_of(&exe);
        assert_eq!(
            state.analyze_executable(dev, ino),
            StaticHint::LinksProvider
        );
        let charged = state.capture_bytes_charged_for_test();
        assert_eq!(state.verdicts_len_for_test(), 1);
        // Unlearned-helper twin: measures the executable-only spans a
        // stale-hit re-analysis legitimately re-reads. The FIFO helper
        // itself must contribute nothing beyond that.
        let mut twin = ExtensiveState::new();
        twin.set_enabled(true);
        twin.set_watched_for_test(vec![watched(&provider, b"libprov.so.1")]);
        twin.learn_scan_path(cache_key_of(&exe), &exe);
        twin.learn_scan_path(cache_key_of(&provider), &provider);
        assert_eq!(twin.analyze_executable(dev, ino), StaticHint::Unknown);
        let exe_only = twin.capture_bytes_charged_for_test();
        replace_with_fifo(&helper);
        assert_eq!(state.analyze_executable(dev, ino), StaticHint::Unknown);
        assert_eq!(
            state.capture_bytes_charged_for_test(),
            charged + exe_only,
            "re-analysis must re-read only the executable, never the fifo helper"
        );
        assert_eq!(state.verdicts_len_for_test(), 0, "stale verdict dropped");
        assert_eq!(state.analyses_run_for_test(), 2);
    }

    #[test]
    fn elf_needed_fifo_exe_cold_refuses_promptly() {
        fifo_child_or_spawn(
            "elf_needed_fifo_exe_cold_refuses_promptly",
            "exe-cold",
            fifo_case_exe_cold,
        );
    }

    #[test]
    fn elf_needed_fifo_exe_cached_refuses_promptly() {
        fifo_child_or_spawn(
            "elf_needed_fifo_exe_cached_refuses_promptly",
            "exe-cached",
            fifo_case_exe_cached,
        );
    }

    #[test]
    fn elf_needed_fifo_intermediate_cold_refuses_promptly() {
        fifo_child_or_spawn(
            "elf_needed_fifo_intermediate_cold_refuses_promptly",
            "helper-cold",
            fifo_case_helper_cold,
        );
    }

    #[test]
    fn elf_needed_fifo_intermediate_cached_refuses_promptly() {
        fifo_child_or_spawn(
            "elf_needed_fifo_intermediate_cached_refuses_promptly",
            "helper-cached",
            fifo_case_helper_cached,
        );
    }

    // 614b round-2 P2#1 controls: a learned path that is a normal
    // symlink to a regular file still analyzes (pinning follows it,
    // then the same-FD checks run), and a regular-file replacement of
    // an intermediate still refuses promptly in-process.
    #[test]
    fn elf_needed_reopen_symlink_and_regular_controls() {
        let dir = tempfile::tempdir().unwrap();
        let provider = write_elf(
            dir.path(),
            "libprov.so.1",
            &build_elf(&ElfSpec::lib(b"libprov.so.1", &[])),
        );
        let helper_real = write_elf(
            dir.path(),
            "helper.real",
            &build_elf(&ElfSpec::lib(b"libhelper.so.1", &[b"libprov.so.1"])),
        );
        let helper_link = dir.path().join("libhelper.so.1");
        std::os::unix::fs::symlink(&helper_real, &helper_link).unwrap();
        let exe_real = write_elf(
            dir.path(),
            "exe.real",
            &build_elf(&ElfSpec::exe(&[b"libhelper.so.1"])),
        );
        let exe_link = dir.path().join("exe");
        std::os::unix::fs::symlink(&exe_real, &exe_link).unwrap();
        let mut state = ExtensiveState::new();
        state.set_enabled(true);
        state.set_watched_for_test(vec![watched(&provider, b"libprov.so.1")]);
        state.learn_scan_path(cache_key_of(&exe_link), &exe_link);
        state.learn_scan_path(cache_key_of(&helper_link), &helper_link);
        state.learn_scan_path(cache_key_of(&provider), &provider);
        let (dev, ino) = record_identity_of(&exe_link);
        assert_eq!(
            state.analyze_executable(dev, ino),
            StaticHint::LinksProvider
        );
        assert_eq!(
            state.analyze_executable(dev, ino),
            StaticHint::LinksProvider
        );
        assert_eq!(state.analyses_run_for_test(), 1);
        // Regular-file replacement of the intermediate refuses promptly.
        std::fs::remove_file(&helper_real).unwrap();
        std::fs::write(
            &helper_real,
            build_elf(&ElfSpec::lib(b"libhelper.so.1", &[b"libprov.so.1"])),
        )
        .unwrap();
        assert_eq!(state.analyze_executable(dev, ino), StaticHint::Unknown);
        assert_eq!(state.analyses_run_for_test(), 2);
    }

    // 614b round-2 P2#2: strtab file-offset translation must use
    // checked arithmetic and validate the full DT_STRSZ span against
    // the containing load's file-backed range. An overflowing offset,
    // a span past the segment end, and a wildly overlong DT_STRSZ are
    // Malformed before any strtab read or charge — in both debug and
    // optimized profiles. Fixture layout notes: the 64-bit builder
    // places PT_LOAD p_offset at file 72 and the DT_STRSZ value at
    // file 216 (dynamic array at 176, third entry); the 32-bit
    // builder places the DT_STRSZ value at file 136 (dynamic array
    // at 116, third entry). Pre-strtab charges are therefore 64 +
    // 112 + 64 (64-bit) and 64 + 64 + 32 (32-bit): the header span
    // is always 64 bytes.
    fn patch_le64(bytes: &mut [u8], at: usize, value: u64) {
        bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn patch_le32(bytes: &mut [u8], at: usize, value: u32) {
        bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// Read one fixture's bytes through the bounded parser with ample
    /// budgets. A translation panic fails the test at the production
    /// line; the parser must return Malformed, never panic.
    fn read_fixture(bytes: &[u8]) -> (Result<ElfNeeded, ElfReadFailure>, u64) {
        let dir = tempfile::tempdir().unwrap();
        let path = write_elf(dir.path(), "case", bytes);
        let file = std::fs::File::open(&path).unwrap();
        let mut charge = 0u64;
        let result = read_elf_needed(&file, &mut charge, 0);
        (result, charge)
    }

    #[test]
    fn elf_needed_strtab_offset_overflow_is_malformed() {
        let mut bytes = build_elf(&ElfSpec::exe(&[b"libprov.so.1"]));
        // PT_LOAD p_offset overflows u64 once the in-range vaddr delta
        // is added; every surrounding span stays small and valid.
        patch_le64(&mut bytes, 72, u64::MAX - 50);
        let (result, charge) = read_fixture(&bytes);
        assert_eq!(result, Err(ElfReadFailure::Malformed));
        assert_eq!(charge, 64 + 112 + 64, "refused strtab span charges nothing");
    }

    #[test]
    fn elf_needed_strtab_span_past_load_end_is_malformed() {
        // Overlong by 100: the span starts in-range but ends past the
        // load's file-backed range.
        let mut bytes = build_elf(&ElfSpec::exe(&[b"libprov.so.1"]));
        patch_le64(&mut bytes, 216, 14 + 100);
        let (result, charge) = read_fixture(&bytes);
        assert_eq!(result, Err(ElfReadFailure::Malformed));
        assert_eq!(charge, 64 + 112 + 64, "refused strtab span charges nothing");
    }

    #[test]
    fn elf_needed_strtab_wildly_overlong_strsz_is_malformed() {
        // 8 MiB of string table claimed inside a ~254-byte load: the
        // span check refuses before the byte budget is even consulted.
        let mut bytes = build_elf(&ElfSpec::exe(&[b"libprov.so.1"]));
        patch_le64(&mut bytes, 216, 8 * 1024 * 1024);
        let (result, charge) = read_fixture(&bytes);
        assert_eq!(result, Err(ElfReadFailure::Malformed));
        assert_eq!(charge, 64 + 112 + 64, "refused strtab span charges nothing");
    }

    #[test]
    fn elf_needed_strtab_span_checked_32bit() {
        let mut spec = ElfSpec::exe(&[b"libprov.so.1"]);
        spec.bits32 = true;
        spec.vaddr_bias = 0x0804_8000;
        let mut bytes = build_elf(&spec);
        patch_le32(&mut bytes, 136, 14 + 100);
        let (result, charge) = read_fixture(&bytes);
        assert_eq!(result, Err(ElfReadFailure::Malformed));
        assert_eq!(charge, 64 + 64 + 32, "refused strtab span charges nothing");
    }

    #[test]
    fn elf_needed_malformed_strtab_stays_unknown_uncached() {
        let mut bytes = build_elf(&ElfSpec::exe(&[b"libprov.so.1"]));
        patch_le64(&mut bytes, 72, u64::MAX - 50);
        let dir = tempfile::tempdir().unwrap();
        let exe = write_elf(dir.path(), "badstr", &bytes);
        let mut state = ExtensiveState::new();
        state.set_enabled(true);
        state.learn_scan_path(cache_key_of(&exe), &exe);
        let (dev, ino) = record_identity_of(&exe);
        assert_eq!(state.analyze_executable(dev, ino), StaticHint::Unknown);
        assert_eq!(state.verdicts_len_for_test(), 0);
        assert_eq!(state.analyses_run_for_test(), 1);
        assert_eq!(state.analyze_executable(dev, ino), StaticHint::Unknown);
        assert_eq!(state.analyses_run_for_test(), 2, "unknown is never cached");
    }
}
