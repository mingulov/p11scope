//! SPDX-License-Identifier: GPL-3.0-or-later
//! The original-file witness for overlay deep scans: after an overlayfs
//! copy-up, a process still running the old lower-layer file keeps a
//! mapping whose `(dev, ino)` equals the fresh upper file, so the
//! deep-scan `(dev, ino)` join would attribute the stale mapper to the
//! fresh file. [`original_file_witness_required`] names that shape; the
//! witness proves the association in the kernel (the existing VMA
//! identity session, one examined anchor plus one target run) or the
//! scan reports the row as unknown with the finite gap
//! `original_file_unproven`. A fresh mapper still joins exactly.
//!
//! The witness never takes a userspace fallback: its confirm IO
//! ([`WitnessNoFallback`]) refuses every `map_files` proof, so a kernel
//! run that is unavailable for any reason yields the gap, never an edge.

use crate::discovery::identity::{ExaminedObject, FileIdentity, MappedFile, PinnedObjects};
use crate::discovery::kernel_identity::{
    AnchorPass, ExaminedCustody, IdentitySession, KernelMemberProbe,
};
use crate::discovery::scan::CaptureWorkBudget;
use crate::discovery::sweep_attribution::{
    Confirmation, KnownKeyIndex, MemberProbe, OsConfirmIo, RangeProof, ReservationOwner,
    SegmentPolicy, Slot, WitnessNoFallback,
};
use p11scope_manifest::identity::OVERLAYFS_SUPER_MAGIC;
use p11scope_manifest::maps::ObjectKey;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Witness queries per deep scan. A provider group normally carries one
/// or two caller ranges; eight covers double loads plus margin while
/// bounding the added scan latency to eight anchor-plus-target runs
/// (milliseconds each; the privileged twins and the D1 cost run pin the
/// per-query wall time). Exhaustion fail-closes to the gap, separate
/// from the sweep's `MAX_TARGET_ATTEMPTS_PER_PASS` (per installed pass —
/// each witness query installs its own pass, so that cap cannot bound
/// the witness).
pub(crate) const OVERLAY_WITNESS_QUERIES_PER_SCAN: u32 = 8;

/// The lone anchor of a single-candidate pass always takes slot zero:
/// candidates are numbered positionally
/// (`kernel_identity.rs`, examined push) and a lone anchor has nothing
/// to alias, so the install cannot remap it. Any deviation (a malformed
/// stream, a non-anchor range) compares unequal and fail-closes to a
/// refusal, never a join.
const WITNESS_SINGLE_ANCHOR_SLOT: Slot = Slot(0);

/// The finite public gap: the scan could not prove the mapping is the
/// held file, so the row is unknown. Failure causes stay internal; the
/// four reason strings below are the whole published vocabulary.
pub(crate) const ORIGINAL_FILE_UNPROVEN: &str = "original_file_unproven";

/// The kernel proved the mapping is another file (the stale shape).
pub(crate) const GAP_WITNESS_REFUSED: &str =
    "original_file_unproven: the kernel witness proved another file";
/// The scan spent its witness budget.
pub(crate) const GAP_BUDGET_EXHAUSTED: &str =
    "original_file_unproven: witness query budget exhausted";
/// The kernel proof could not run (no anchor, deadline, failed run).
pub(crate) const GAP_WITNESS_UNAVAILABLE: &str =
    "original_file_unproven: kernel witness unavailable";
/// The held file could not be installed as the witness anchor.
pub(crate) const GAP_ANCHOR_BINDING_FAILED: &str =
    "original_file_unproven: witness anchor binding failed";

/// Whether the held file plus the target identity needs the witness: the
/// held file sits on overlayfs (or its filesystem is unproven, fail
/// closed) and the target range's `(dev, ino)` equals the held file, so
/// equality alone cannot tell a stale lower mapping from the fresh
/// upper one. There is deliberately no kernel-version arm: on older
/// kernels the stale mapping already separates by `(dev, ino)` (the
/// legacy refusal, no witness spent) and the fresh one proves like on
/// newer kernels.
pub(crate) fn original_file_witness_required(held: &MappedFile, target: &FileIdentity) -> bool {
    held.fs_magic
        .is_none_or(|magic| magic == OVERLAYFS_SUPER_MAGIC)
        && target == &held.identity
}

/// Why a witness query failed. Internal: the public surface is the gap
/// reason ([`WitnessVerdict::gap_reason`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WitnessFailure {
    BudgetExhausted,
    Unavailable,
    AnchorBindingFailed,
}

/// What one witness query concluded about the trigger range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WitnessVerdict {
    SameFile,
    OtherFile,
    Failed(WitnessFailure),
}

impl WitnessVerdict {
    /// The gap reason for a refusal, or `None` for a join. The four
    /// strings are fixed: no pids, paths, addresses or run detail.
    pub(crate) fn gap_reason(&self) -> Option<&'static str> {
        let reason = match self {
            WitnessVerdict::SameFile => None,
            WitnessVerdict::OtherFile => Some(GAP_WITNESS_REFUSED),
            WitnessVerdict::Failed(WitnessFailure::BudgetExhausted) => Some(GAP_BUDGET_EXHAUSTED),
            WitnessVerdict::Failed(WitnessFailure::Unavailable) => Some(GAP_WITNESS_UNAVAILABLE),
            WitnessVerdict::Failed(WitnessFailure::AnchorBindingFailed) => {
                Some(GAP_ANCHOR_BINDING_FAILED)
            }
        };
        if let Some(reason) = reason {
            debug_assert!(
                reason.starts_with(ORIGINAL_FILE_UNPROVEN),
                "gap reason without the finite prefix"
            );
        }
        reason
    }

    fn log_word(&self) -> &'static str {
        match self {
            WitnessVerdict::SameFile => "same_file",
            WitnessVerdict::OtherFile => "other_file",
            WitnessVerdict::Failed(WitnessFailure::BudgetExhausted) => "budget_exhausted",
            WitnessVerdict::Failed(WitnessFailure::Unavailable) => "unavailable",
            WitnessVerdict::Failed(WitnessFailure::AnchorBindingFailed) => "anchor_binding_failed",
        }
    }
}

/// The process-wide witness session. One session serves every deep scan
/// (loading per query would dwarf the millisecond run cost); the sweep
/// cannot lend its session because the userspace backend has none and
/// the witness must behave identically under every backend. Queries run
/// serialized under one lock; a failed load is remembered so later
/// queries fail fast instead of retrying a doomed load.
struct WitnessSession {
    session: Option<IdentitySession>,
    generation: u64,
    unavailable: Option<&'static str>,
}

static WITNESS_SESSION: OnceLock<Mutex<WitnessSession>> = OnceLock::new();
static WITNESS_QUERIES: AtomicU64 = AtomicU64::new(0);
static WITNESS_NANOS: AtomicU64 = AtomicU64::new(0);

/// Completed witness queries and their total wall time, for the cost
/// cells. Production runs read the same numbers from the gated timing
/// lines; tests read them here.
#[cfg(test)]
pub(crate) fn witness_stats_for_test() -> (u64, u64) {
    (
        WITNESS_QUERIES.load(Ordering::SeqCst),
        WITNESS_NANOS.load(Ordering::SeqCst),
    )
}

fn witness_session() -> &'static Mutex<WitnessSession> {
    WITNESS_SESSION.get_or_init(|| {
        Mutex::new(WitnessSession {
            session: None,
            generation: 0,
            unavailable: None,
        })
    })
}

/// Prove the trigger range of `pid` is the scan's held file: install a
/// dup of the held fd (never a path reopen) as one examined anchor,
/// confirm the target with a probe that cannot fall back, and read the
/// trigger range's kernel proof directly. Anything unexpected —
/// including a lock, load, install, run or shape anomaly — is
/// [`WitnessFailure::Unavailable`] or [`WitnessFailure::AnchorBindingFailed`],
/// never a join.
pub(crate) fn prove_original_file(
    pid: u32,
    file: &File,
    held: &MappedFile,
    key: ObjectKey,
    range: (u64, u64),
    budget: &mut CaptureWorkBudget,
) -> WitnessVerdict {
    // Scoped collection deliberately deactivates the kernel proof
    // substrate; the witness stays off there too, without spending a
    // session, FDs or runs.
    if budget.has_collection_work() {
        return WitnessVerdict::Failed(WitnessFailure::Unavailable);
    }
    if budget.check_deadline_now().is_some() {
        return WitnessVerdict::Failed(WitnessFailure::Unavailable);
    }
    let started = Instant::now();
    let verdict = prove_original_file_inner(pid, file, held, key, range, budget);
    let wall = started.elapsed();
    WITNESS_QUERIES.fetch_add(1, Ordering::SeqCst);
    WITNESS_NANOS.fetch_add(wall.as_nanos() as u64, Ordering::SeqCst);
    if crate::inspect_system::stage_timings_requested() {
        eprintln!(
            "p11scope: overlay-witness verdict={} wall_ms={}",
            verdict.log_word(),
            wall.as_millis()
        );
    }
    verdict
}

fn prove_original_file_inner(
    pid: u32,
    file: &File,
    held: &MappedFile,
    key: ObjectKey,
    range: (u64, u64),
    budget: &mut CaptureWorkBudget,
) -> WitnessVerdict {
    let anchor = match file.try_clone() {
        Ok(anchor) => anchor,
        Err(_) => return WitnessVerdict::Failed(WitnessFailure::Unavailable),
    };
    let mut guard = match witness_session().lock() {
        Ok(guard) => guard,
        Err(_) => return WitnessVerdict::Failed(WitnessFailure::Unavailable),
    };
    if let Some(reason) = guard.unavailable {
        let _ = reason;
        return WitnessVerdict::Failed(WitnessFailure::Unavailable);
    }
    if guard.session.is_none() {
        match load_witness_session() {
            Ok(session) => guard.session = Some(session),
            Err(reason) => {
                guard.unavailable = Some(reason);
                return WitnessVerdict::Failed(WitnessFailure::Unavailable);
            }
        }
    }
    // The install/run ceiling starts after the one-time session load:
    // the load is process setup (like the capture's), not query work,
    // and must not eat the query's deadline. A capture that expired
    // during the load still fail-closes here.
    if budget.check_deadline_now().is_some() {
        return WitnessVerdict::Failed(WitnessFailure::Unavailable);
    }
    let deadline = witness_deadline(budget);
    let Some(deadline) = deadline else {
        return WitnessVerdict::Failed(WitnessFailure::Unavailable);
    };
    let owner = match SegmentPolicy::try_snapshot(0, 0) {
        Ok(policy) => ReservationOwner::for_examined(policy, 1),
        Err(_) => return WitnessVerdict::Failed(WitnessFailure::Unavailable),
    };
    let mut custody = ExaminedCustody::new(owner, BTreeMap::new());
    let scan = custody.begin_scan();
    let examined = ExaminedObject {
        key,
        identity: held.identity,
        key_is_identity: held.key_is_identity(key),
    };
    if !custody.offer(scan, examined, anchor) {
        return WitnessVerdict::Failed(WitnessFailure::Unavailable);
    }
    let reconciled = (|| {
        let policy = SegmentPolicy::try_snapshot(1, 1).ok()?;
        custody.reconcile(policy).ok()
    })();
    if reconciled.is_none() {
        return WitnessVerdict::Failed(WitnessFailure::Unavailable);
    }
    let pins = PinnedObjects::empty();
    let pass = AnchorPass::prepare_excluding(
        &pins,
        std::iter::empty(),
        custody,
        budget.kernel_anchor_exclusions(),
    );
    if pass.fallback.contains_key(&key) {
        return WitnessVerdict::Failed(WitnessFailure::AnchorBindingFailed);
    }
    let Some(generation) = guard.generation.checked_add(1) else {
        return WitnessVerdict::Failed(WitnessFailure::Unavailable);
    };
    guard.generation = generation;
    let session = guard.session.as_mut().expect("witness session is loaded");
    let mut installed = match session.install_anchors(pass, generation, deadline) {
        Ok(installed) => installed,
        Err(_) => return WitnessVerdict::Failed(WitnessFailure::AnchorBindingFailed),
    };
    let (mut index, _) =
        KnownKeyIndex::build(std::iter::empty(), &BTreeMap::new(), [examined], &pins);
    let mut probe = KernelMemberProbe::new(
        &mut installed,
        WitnessNoFallback::new(OsConfirmIo::with_pool(None)),
        deadline,
    );
    if probe.install_expectations(&mut index).is_err() {
        return WitnessVerdict::Failed(WitnessFailure::AnchorBindingFailed);
    }
    let confirmation = probe.confirm(pid, &BTreeSet::from([key]), budget);
    drop(probe);
    drop(installed);
    verdict_for_confirmation(&confirmation, range)
}

fn load_witness_session() -> Result<IdentitySession, &'static str> {
    crate::attach::identity_iter::ensure_kernel_identity_btf().map_err(|_| "no BTF")?;
    let parsed = aya::Btf::from_sys_fs().map_err(|_| "no BTF")?;
    let dir = WitnessProbeDir::create()?;
    IdentitySession::probe_and_load(&parsed, dir.path()).map_err(|_| "load failed")
}

/// A securely created empty probe dir for the witness's functional
/// probe, removed on drop. Mirrors `inspect_system::ProbeDir` (which the
/// witness cannot reuse across modules): an unpredictable 0700 name,
/// every check against the open fd, and cleanup that unlinks only the
/// four fixture names through the held dirfd, never the path.
struct WitnessProbeDir {
    path: std::path::PathBuf,
    uid: u32,
    dev: libc::dev_t,
    ino: libc::ino_t,
    dirfd: std::os::fd::OwnedFd,
}

impl WitnessProbeDir {
    fn create() -> Result<Self, &'static str> {
        let seed = std::collections::hash_map::RandomState::new();
        let random = {
            use std::hash::BuildHasher as _;
            seed.hash_one(std::process::id())
        };
        let path = std::env::temp_dir().join(format!(
            "p11scope-witness-probe-{}-{random:016x}",
            std::process::id()
        ));
        Self::create_at(&path)
    }

    fn create_at(path: &std::path::Path) -> Result<Self, &'static str> {
        use std::os::fd::{AsRawFd as _, FromRawFd as _};
        use std::os::unix::ffi::OsStrExt as _;
        let cpath =
            std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| "no probe dir")?;
        // SAFETY: `mkdir` of a NUL-terminated path. Atomic: any
        // pre-existing name (dir, file or symlink) fails instead of
        // being adopted.
        if unsafe { libc::mkdir(cpath.as_ptr(), 0o700) } != 0 {
            return Err("no probe dir");
        }
        // Pin the fresh directory before verifying it: every check and
        // the mode fix below run against the open fd, never the path.
        // SAFETY: `open` of a NUL-terminated path; `O_NOFOLLOW` refuses
        // a swapped-in symlink instead of following it.
        let raw = unsafe {
            libc::open(
                cpath.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            // Best-effort cleanup of the directory mkdir just made.
            // `rmdir` removes empty dirs only, so a swapped-in foreign
            // path loses at most an empty dir — never contents.
            unsafe {
                libc::rmdir(cpath.as_ptr());
            }
            return Err("no probe dir");
        }
        // SAFETY: the successful `open` returned a new owned fd.
        let dirfd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) };
        // SAFETY: `fstat` on a live fd with a writable out-param.
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(dirfd.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            drop(dirfd);
            unsafe {
                libc::rmdir(cpath.as_ptr());
            }
            return Err("no probe dir");
        }
        // SAFETY: the successful `fstat` initialized `stat`.
        let stat = unsafe { stat.assume_init() };
        // SAFETY: `geteuid` takes no arguments and always succeeds.
        let uid = unsafe { libc::geteuid() };
        if stat.st_mode & libc::S_IFMT != libc::S_IFDIR || stat.st_uid != uid {
            drop(dirfd);
            unsafe {
                libc::rmdir(cpath.as_ptr());
            }
            return Err("no probe dir");
        }
        // Only the verified-owned fd is modified: the mkdir mode honors
        // umask, so enforce 0700 exactly here.
        if unsafe { libc::fchmod(dirfd.as_raw_fd(), 0o700) } != 0 {
            drop(dirfd);
            unsafe {
                libc::rmdir(cpath.as_ptr());
            }
            return Err("no probe dir");
        }
        Ok(Self {
            path: path.to_path_buf(),
            uid,
            dev: stat.st_dev,
            ino: stat.st_ino,
            dirfd,
        })
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Whether `path` is still the directory this value created: the
    /// same device/inode directory owned by the creation uid.
    fn owns(path: &std::path::Path, uid: u32, dev: libc::dev_t, ino: libc::ino_t) -> bool {
        use std::os::unix::ffi::OsStrExt as _;
        let Ok(cpath) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `lstat` as in `create_at`.
        if unsafe { libc::lstat(cpath.as_ptr(), stat.as_mut_ptr()) } != 0 {
            return false;
        }
        // SAFETY: the successful `lstat` initialized `stat`.
        let stat = unsafe { stat.assume_init() };
        stat.st_mode & libc::S_IFMT == libc::S_IFDIR
            && stat.st_uid == uid
            && stat.st_dev == dev
            && stat.st_ino == ino
    }
}

impl Drop for WitnessProbeDir {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd as _;
        if !Self::owns(&self.path, self.uid, self.dev, self.ino) {
            return;
        }
        // Bounded cleanup, not a recursive delete: only the four
        // fixture names the probe writes are unlinked, through the
        // held directory fd (never the path).
        for name in [c"probe-a", c"probe-b", c"probe-a-link", c"probe-a-copy"] {
            // SAFETY: `unlinkat` of a static NUL-terminated name on
            // the live held dirfd; flags 0 never unlinks directories.
            unsafe {
                libc::unlinkat(self.dirfd.as_raw_fd(), name.as_ptr(), 0);
            }
        }
        use std::os::unix::ffi::OsStrExt as _;
        if let Ok(cpath) = std::ffi::CString::new(self.path.as_os_str().as_bytes()) {
            // SAFETY: `rmdir` of a NUL-terminated path; removes empty
            // dirs only.
            unsafe {
                libc::rmdir(cpath.as_ptr());
            }
        }
    }
}

/// One query's ceiling: 500 ms like every target run, clamped by the
/// capture deadline. `None` when the capture is already over deadline.
fn witness_deadline(budget: &CaptureWorkBudget) -> Option<Instant> {
    let now = Instant::now();
    let mut deadline = now + Duration::from_millis(500);
    if let Some(limit) = budget.effective_deadline_ns() {
        let clock = crate::attach::monotonic_ns()?;
        let left = limit.checked_sub(clock)?;
        deadline = deadline.min(now.checked_add(Duration::from_nanos(left))?);
    }
    if Instant::now() >= deadline {
        return None;
    }
    Some(deadline)
}

/// Read the trigger range's kernel proof directly. Only the lone
/// anchor's slot joins; a userspace proof is impossible by construction
/// (the confirm IO refuses it) and fail-closes if ever seen.
fn verdict_for_confirmation(confirmation: &Confirmation, range: (u64, u64)) -> WitnessVerdict {
    let Confirmation::Confirmed(read) = confirmation else {
        return WitnessVerdict::Failed(WitnessFailure::Unavailable);
    };
    match read.mapped.get(&range) {
        Some(RangeProof::Kernel(slot)) if *slot == WITNESS_SINGLE_ANCHOR_SLOT => {
            WitnessVerdict::SameFile
        }
        Some(RangeProof::Kernel(_)) | Some(RangeProof::KernelNone) => WitnessVerdict::OtherFile,
        _ => WitnessVerdict::Failed(WitnessFailure::Unavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overlay_held() -> MappedFile {
        MappedFile {
            identity: FileIdentity { dev: 42, ino: 7 },
            fs_magic: Some(OVERLAYFS_SUPER_MAGIC),
        }
    }

    #[test]
    fn predicate_requires_overlay_and_equality() {
        let held = overlay_held();
        assert!(original_file_witness_required(&held, &held.identity));
        let other = FileIdentity { dev: 42, ino: 9 };
        assert!(!original_file_witness_required(&held, &other));
        let ext4 = MappedFile {
            identity: held.identity,
            fs_magic: Some(0xef53),
        };
        assert!(!original_file_witness_required(&ext4, &held.identity));
        assert!(!original_file_witness_required(&ext4, &other));
    }

    #[test]
    fn predicate_fails_closed_on_unproven_filesystem() {
        let held = MappedFile {
            identity: FileIdentity { dev: 42, ino: 7 },
            fs_magic: None,
        };
        assert!(original_file_witness_required(&held, &held.identity));
        let other = FileIdentity { dev: 42, ino: 9 };
        assert!(!original_file_witness_required(&held, &other));
    }

    #[test]
    fn gap_reasons_are_four_fixed_strings() {
        assert_eq!(ORIGINAL_FILE_UNPROVEN, "original_file_unproven");
        let reasons = [
            (
                WitnessVerdict::OtherFile,
                "original_file_unproven: the kernel witness proved another file",
            ),
            (
                WitnessVerdict::Failed(WitnessFailure::BudgetExhausted),
                "original_file_unproven: witness query budget exhausted",
            ),
            (
                WitnessVerdict::Failed(WitnessFailure::Unavailable),
                "original_file_unproven: kernel witness unavailable",
            ),
            (
                WitnessVerdict::Failed(WitnessFailure::AnchorBindingFailed),
                "original_file_unproven: witness anchor binding failed",
            ),
        ];
        for (verdict, expected) in reasons {
            assert_eq!(verdict.gap_reason(), Some(expected));
            assert!(expected.starts_with(ORIGINAL_FILE_UNPROVEN));
        }
        assert_eq!(WitnessVerdict::SameFile.gap_reason(), None);
    }

    #[test]
    fn budget_size_is_pinned() {
        assert_eq!(OVERLAY_WITNESS_QUERIES_PER_SCAN, 8);
    }

    fn confirmed_with(
        mapped: crate::discovery::sweep_attribution::MappedIdentities,
    ) -> Confirmation {
        Confirmation::Confirmed(crate::discovery::sweep_attribution::ConfirmedRead {
            start_time: 1,
            exe: crate::discovery::caller_registry::ExeIdentity {
                dev: 1,
                ino: 2,
                mtime_secs: 0,
                mtime_nanos: 0,
                path: None,
            },
            entries: Vec::new(),
            mapped,
        })
    }

    #[test]
    fn verdict_joins_only_the_anchor_slot() {
        let range = (0x7f00_0000, 0x7f00_1000);
        let mapped = BTreeMap::from([(range, RangeProof::Kernel(WITNESS_SINGLE_ANCHOR_SLOT))]);
        assert_eq!(
            verdict_for_confirmation(&confirmed_with(mapped), range),
            WitnessVerdict::SameFile
        );
        for proof in [
            RangeProof::Kernel(Slot(1)),
            RangeProof::Kernel(Slot(u32::MAX)),
            RangeProof::KernelNone,
        ] {
            let mapped = BTreeMap::from([(range, proof)]);
            assert_eq!(
                verdict_for_confirmation(&confirmed_with(mapped), range),
                WitnessVerdict::OtherFile,
                "a kernel non-membership proof refuses, never joins"
            );
        }
    }

    #[test]
    fn verdict_fail_closes_everything_else() {
        let range = (0x7f00_0000, 0x7f00_1000);
        let unavailable = WitnessVerdict::Failed(WitnessFailure::Unavailable);
        let identity = FileIdentity { dev: 42, ino: 7 };
        for proof in [
            RangeProof::MapFiles(identity),
            RangeProof::Unavailable("the original-file witness refuses userspace proof".into()),
            RangeProof::NotMapped,
        ] {
            let mapped = BTreeMap::from([(range, proof)]);
            assert_eq!(
                verdict_for_confirmation(&confirmed_with(mapped), range),
                unavailable
            );
        }
        assert_eq!(
            verdict_for_confirmation(&confirmed_with(BTreeMap::new()), range),
            unavailable,
            "an unproven range never joins"
        );
        assert_eq!(
            verdict_for_confirmation(
                &Confirmation::Lost(
                    crate::discovery::sweep_attribution::AttributionLoss::MapFilesUnavailable,
                    "refused".into()
                ),
                range
            ),
            unavailable
        );
        assert_eq!(
            verdict_for_confirmation(&Confirmation::Exited, range),
            unavailable
        );
    }

    #[test]
    fn scoped_collection_skips_the_witness() {
        let held = overlay_held();
        let mut budget = CaptureWorkBudget::default();
        budget.set_collection_work(crate::discovery::scan::CollectionWork::new(|_| true));
        let file = File::open("/dev/null").unwrap();
        let (queries_before, _) = witness_stats_for_test();
        let verdict = prove_original_file(
            std::process::id(),
            &file,
            &held,
            ObjectKey {
                device: p11scope_manifest::maps::Device {
                    major: 0,
                    minor: 42,
                },
                inode: 7,
            },
            (0x7f00_0000, 0x7f00_1000),
            &mut budget,
        );
        assert_eq!(verdict, WitnessVerdict::Failed(WitnessFailure::Unavailable));
        let (queries_after, _) = witness_stats_for_test();
        assert_eq!(
            queries_before, queries_after,
            "a scoped-collection early-out is not a query"
        );
    }
}
