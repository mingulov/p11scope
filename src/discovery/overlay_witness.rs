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
    AnchorPass, ExaminedCustody, IdentitySession, KernelAnchorExclusions, KernelMemberProbe,
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

/// Witness queries per sweep pass for watched overlay keys with no sweep
/// kernel route (live capture: attach-set exclusions refuse their sweep
/// anchors). D-P1 budget: one private-session query per watched
/// (pid, key), same 8-query bound as a deep scan; exhaustion keeps the
/// named `overlay_kernel_unavailable` loss, never a userspace join.
/// Attempt-cap, cgroup and oversized paths take no witness query.
pub(crate) const OVERLAY_SWEEP_WITNESS_QUERIES_PER_PASS: u32 = 8;

/// The sweep's kernel witness for overlay keys with no sweep route.
/// Production runs the private session below; tests script verdicts.
pub(crate) trait SweepWitness {
    fn prove(
        &mut self,
        pid: u32,
        file: &File,
        held: &MappedFile,
        key: ObjectKey,
        ranges: &[(u64, u64)],
        budget: &mut CaptureWorkBudget,
    ) -> WitnessVerdict;
}

/// Production sweep witness: the private session with no attach-set
/// exclusions, under the per-pass D-P1 budget.
pub(crate) struct KernelSweepWitness {
    used: u32,
}

impl KernelSweepWitness {
    pub(crate) fn new() -> Self {
        Self { used: 0 }
    }

    /// Queries spent so far: the pass advances its witness rotation
    /// by this count, so the next pass continues past the candidates
    /// this pass already proved.
    pub(crate) fn used(&self) -> u32 {
        self.used
    }
}

impl SweepWitness for KernelSweepWitness {
    fn prove(
        &mut self,
        pid: u32,
        file: &File,
        held: &MappedFile,
        key: ObjectKey,
        ranges: &[(u64, u64)],
        budget: &mut CaptureWorkBudget,
    ) -> WitnessVerdict {
        if self.used >= OVERLAY_SWEEP_WITNESS_QUERIES_PER_PASS {
            return WitnessVerdict::Failed(WitnessFailure::BudgetExhausted);
        }
        self.used += 1;
        prove_original_file(pid, file, held, key, ranges, budget)
    }
}

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

/// Mint the next witness generation. Each query mints fresh under the
/// session lock and holds the lock across install and confirm, so both
/// share exactly one generation: a stale-generation confirmation cannot
/// validate, and the only generation failure is counter overflow, which
/// fail-closes unavailable.
fn next_witness_generation(current: u64) -> Option<u64> {
    current.checked_add(1)
}

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

/// Load the process-wide witness session unless already loaded or
/// already failed. Shared by the preload and the lazy query path so
/// the two cannot diverge: a failed load remembers unavailable and
/// later calls fail fast without retrying.
fn ensure_session_loaded(guard: &mut WitnessSession) -> bool {
    if guard.session.is_some() {
        return true;
    }
    if guard.unavailable.is_some() {
        return false;
    }
    match load_witness_session() {
        Ok(session) => {
            guard.session = Some(session);
            true
        }
        Err(reason) => {
            guard.unavailable = Some(reason);
            false
        }
    }
}

/// Load the process-wide witness session now, outside any
/// time-critical path. The one-time load (BPF verifier plus
/// functional probe) is process setup, not query work: run lazily on
/// the first overlay join it can exceed a 500ms pause-cycle engine
/// apply and fail-close the query unavailable. Owned runs call this
/// before spawning the child; a failed load remembers unavailable
/// exactly like the lazy path, so behavior only ever moves earlier.
pub(crate) fn preload_session() {
    let mut guard = match witness_session().lock() {
        Ok(guard) => guard,
        Err(_) => return,
    };
    ensure_session_loaded(&mut guard);
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
    ranges: &[(u64, u64)],
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
    let verdict = prove_original_file_inner(pid, file, held, key, ranges, budget);
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
    ranges: &[(u64, u64)],
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
    if !ensure_session_loaded(&mut guard) {
        return WitnessVerdict::Failed(WitnessFailure::Unavailable);
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
    // The witness session is private (own BPF maps, own fresh arena per
    // pass) and maps only the scan's freshly opened file, never a
    // retained lease — so the sweep's capture-anchor exclusions do not
    // apply here. Honoring them refuses every provider key the live
    // capture watches (the D1 shape); the pass builds exclusion-free,
    // exactly like the experiment's `AnchorPass::prepare`.
    let no_exclusions = KernelAnchorExclusions::default();
    let pass = AnchorPass::prepare_excluding(&pins, std::iter::empty(), custody, &no_exclusions);
    if pass.fallback.contains_key(&key) {
        return WitnessVerdict::Failed(WitnessFailure::AnchorBindingFailed);
    }
    let Some(generation) = next_witness_generation(guard.generation) else {
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
    verdict_for_confirmation(&confirmation, ranges)
}

fn load_witness_session() -> Result<IdentitySession, &'static str> {
    crate::attach::identity_iter::ensure_kernel_identity_btf().map_err(|_| "no BTF")?;
    let parsed = aya::Btf::from_sys_fs().map_err(|_| "no BTF")?;
    let dir = crate::inspect_system::ProbeDir::create("p11scope-witness-probe")
        .map_err(|_| "no probe dir")?;
    IdentitySession::probe_and_load(&parsed, dir.path()).map_err(|_| "load failed")
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

/// Read every refused range's kernel proof from the one confirmation.
/// Only the lone anchor's slot joins, and only when every refused
/// range proves it; one another-file range refuses the whole key, one
/// unproven range fails it closed. A userspace proof is impossible by
/// construction (the confirm IO refuses it) and fail-closes if seen.
fn verdict_for_confirmation(confirmation: &Confirmation, ranges: &[(u64, u64)]) -> WitnessVerdict {
    let Confirmation::Confirmed(read) = confirmation else {
        return WitnessVerdict::Failed(WitnessFailure::Unavailable);
    };
    let mut other = false;
    let mut unknown = false;
    for range in ranges {
        match read.mapped.get(range) {
            Some(RangeProof::Kernel(slot)) if *slot == WITNESS_SINGLE_ANCHOR_SLOT => {}
            Some(RangeProof::Kernel(_)) | Some(RangeProof::KernelNone) => other = true,
            _ => unknown = true,
        }
    }
    if other {
        WitnessVerdict::OtherFile
    } else if unknown || ranges.is_empty() {
        WitnessVerdict::Failed(WitnessFailure::Unavailable)
    } else {
        WitnessVerdict::SameFile
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

    #[test]
    fn generation_mint_increments_and_overflow_fail_closes() {
        assert_eq!(next_witness_generation(0), Some(1));
        assert_eq!(next_witness_generation(7), Some(8));
        assert_eq!(next_witness_generation(u64::MAX), None);
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
            verdict_for_confirmation(&confirmed_with(mapped), &[range]),
            WitnessVerdict::SameFile
        );
        for proof in [
            RangeProof::Kernel(Slot(1)),
            RangeProof::Kernel(Slot(u32::MAX)),
            RangeProof::KernelNone,
        ] {
            let mapped = BTreeMap::from([(range, proof)]);
            assert_eq!(
                verdict_for_confirmation(&confirmed_with(mapped), &[range]),
                WitnessVerdict::OtherFile,
                "a kernel non-membership proof refuses, never joins"
            );
        }
    }

    #[test]
    fn verdict_joins_when_every_refused_range_matches() {
        let fresh = (0x7f00_0000, 0x7f00_1000);
        let fresh2 = (0x7f00_1000, 0x7f00_2000);
        let mapped = BTreeMap::from([
            (fresh, RangeProof::Kernel(WITNESS_SINGLE_ANCHOR_SLOT)),
            (fresh2, RangeProof::Kernel(WITNESS_SINGLE_ANCHOR_SLOT)),
        ]);
        assert_eq!(
            verdict_for_confirmation(&confirmed_with(mapped), &[fresh, fresh2]),
            WitnessVerdict::SameFile
        );
    }

    #[test]
    fn verdict_refuses_when_any_refused_range_proves_another_file() {
        // RED: the mixed-mapping corner (one range same-file, one
        // range another file) must refuse the whole key, not join on
        // the first range.
        let fresh = (0x7f00_0000, 0x7f00_1000);
        let stale = (0x7f00_1000, 0x7f00_2000);
        for proof in [
            RangeProof::Kernel(Slot(1)),
            RangeProof::Kernel(Slot(u32::MAX)),
            RangeProof::KernelNone,
        ] {
            let mapped = BTreeMap::from([
                (fresh, RangeProof::Kernel(WITNESS_SINGLE_ANCHOR_SLOT)),
                (stale, proof),
            ]);
            assert_eq!(
                verdict_for_confirmation(&confirmed_with(mapped), &[fresh, stale]),
                WitnessVerdict::OtherFile,
                "one stale range refuses the whole key"
            );
        }
    }

    #[test]
    fn verdict_is_unavailable_when_any_refused_range_is_unproven() {
        // RED: a refused range with no proof in the confirmation
        // (unmapped since the sweep read) fail-closes the whole key.
        let fresh = (0x7f00_0000, 0x7f00_1000);
        let gone = (0x7f00_1000, 0x7f00_2000);
        let mapped = BTreeMap::from([(fresh, RangeProof::Kernel(WITNESS_SINGLE_ANCHOR_SLOT))]);
        assert_eq!(
            verdict_for_confirmation(&confirmed_with(mapped), &[fresh, gone]),
            WitnessVerdict::Failed(WitnessFailure::Unavailable)
        );
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
                verdict_for_confirmation(&confirmed_with(mapped), &[range]),
                unavailable
            );
        }
        assert_eq!(
            verdict_for_confirmation(&confirmed_with(BTreeMap::new()), &[range]),
            unavailable,
            "an unproven range never joins"
        );
        assert_eq!(
            verdict_for_confirmation(
                &Confirmation::Lost(
                    crate::discovery::sweep_attribution::AttributionLoss::MapFilesUnavailable,
                    "refused".into()
                ),
                &[range]
            ),
            unavailable
        );
        assert_eq!(
            verdict_for_confirmation(&Confirmation::Exited, &[range]),
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
            &[(0x7f00_0000, 0x7f00_1000)],
            &mut budget,
        );
        assert_eq!(verdict, WitnessVerdict::Failed(WitnessFailure::Unavailable));
        let (queries_after, _) = witness_stats_for_test();
        assert_eq!(
            queries_before, queries_after,
            "a scoped-collection early-out is not a query"
        );
    }

    #[test]
    fn sweep_budget_size_is_pinned() {
        assert_eq!(OVERLAY_SWEEP_WITNESS_QUERIES_PER_PASS, 8);
    }

    #[test]
    fn diagnosed_collection_work_skips_uncounted_with_stage() {
        // RED: a scoped-collection early-out is not a query, but the
        // refusal must still name its stage in plain words.
        let held = overlay_held();
        let mut budget = CaptureWorkBudget::default();
        budget.set_collection_work(crate::discovery::scan::CollectionWork::new(|_| true));
        let file = File::open("/dev/null").unwrap();
        let outcome = prove_original_file_diagnosed(
            std::process::id(),
            &file,
            &held,
            ObjectKey {
                device: p11scope_manifest::maps::Device { major: 0, minor: 42 },
                inode: 7,
            },
            &[(0x7f00_0000, 0x7f00_1000)],
            &mut budget,
        );
        assert_eq!(
            outcome.verdict,
            WitnessVerdict::Failed(WitnessFailure::Unavailable)
        );
        let diagnosis = outcome
            .diagnosis
            .expect("an unavailable verdict carries its stage");
        assert_eq!(diagnosis.stage, WitnessStage::CollectionWork);
        assert!(
            !diagnosis.counted,
            "a scoped-collection early-out is not a query"
        );
        assert_eq!(
            diagnosis.enriched_reason(),
            "original_file_unproven: kernel witness unavailable: \
             scoped collection deactivates the kernel proof"
        );
    }

    #[test]
    fn diagnosed_spent_deadline_skips_uncounted_with_stage() {
        // RED: a query past the capture deadline never runs, and the
        // refusal names the spent deadline.
        let held = overlay_held();
        let mut budget = CaptureWorkBudget::default();
        budget.set_deadline(Some(0));
        let file = File::open("/dev/null").unwrap();
        let outcome = prove_original_file_diagnosed(
            std::process::id(),
            &file,
            &held,
            ObjectKey {
                device: p11scope_manifest::maps::Device { major: 0, minor: 42 },
                inode: 7,
            },
            &[(0x7f00_0000, 0x7f00_1000)],
            &mut budget,
        );
        assert_eq!(
            outcome.verdict,
            WitnessVerdict::Failed(WitnessFailure::Unavailable)
        );
        let diagnosis = outcome
            .diagnosis
            .expect("an unavailable verdict carries its stage");
        assert_eq!(diagnosis.stage, WitnessStage::DeadlineSpent);
        assert!(!diagnosis.counted, "a spent-deadline early-out is not a query");
    }

    #[test]
    fn deny_maps_to_btf_stages() {
        // RED: the BTF selection deny keeps its label, never its raw detail.
        use crate::attach::identity_iter::KernelDeny;
        assert_eq!(
            diagnosis_for_deny(&KernelDeny::FixMissing).stage,
            WitnessStage::BtfFixMissing
        );
        assert_eq!(
            diagnosis_for_deny(&KernelDeny::NoTaskIterPidfd).stage,
            WitnessStage::BtfNoTaskIterPidfd
        );
        assert_eq!(
            diagnosis_for_deny(&KernelDeny::NoBtf("/sys/kernel/btf/vmlinux: gone".into())).stage,
            WitnessStage::BtfUnreadable
        );
    }

    #[test]
    fn load_error_maps_to_object_stages() {
        // RED: the object-load failure names permission vs verifier vs a
        // missing program vs an unretainable fd.
        use crate::attach::identity_iter::LoadError;
        fn syscall_errno(errno: i32) -> LoadError {
            LoadError::Program(aya::programs::ProgramError::SyscallError(
                aya::sys::SyscallError {
                    call: "bpf",
                    io_error: std::io::Error::from_raw_os_error(errno),
                },
            ))
        }
        assert_eq!(
            diagnosis_for_load_error(&syscall_errno(libc::EPERM)).stage,
            WitnessStage::ObjectLoadPermission
        );
        assert_eq!(
            diagnosis_for_load_error(&syscall_errno(libc::EINVAL)).stage,
            WitnessStage::ObjectLoadFailed
        );
        assert_eq!(
            diagnosis_for_load_error(&LoadError::MissingProgram("p11_anchor_vma")).stage,
            WitnessStage::ObjectLoadMissingProgram
        );
        assert_eq!(
            diagnosis_for_load_error(&LoadError::FdClone(std::io::Error::other("clone"))).stage,
            WitnessStage::ObjectLoadFdRetain
        );
    }

    #[test]
    fn probe_failure_maps_to_probe_stage_without_raw_detail() {
        // RED: the functional-probe failure names its stage tag; the raw
        // probe detail (paths, pids) never reaches the note.
        use crate::attach::identity_iter::ProbeError;
        use crate::discovery::kernel_identity::IdentityLoadFailure;
        let failed = IdentityLoadFailure::ProbeFailed(ProbeError {
            stage: "scope-write",
            detail: "SECRET-RAW-DETAIL".into(),
        });
        let diagnosis = diagnosis_for_identity_load_failure(&failed);
        assert_eq!(
            diagnosis.stage,
            WitnessStage::FunctionalProbe { stage: "scope-write" }
        );
        assert!(diagnosis.note().contains("scope-write"));
        assert!(
            !diagnosis.note().contains("SECRET-RAW-DETAIL"),
            "raw probe detail never leaks: {}",
            diagnosis.note()
        );
        let mismatch = IdentityLoadFailure::ProbeMismatch;
        assert_eq!(
            diagnosis_for_identity_load_failure(&mismatch).stage,
            WitnessStage::ProbeMismatch
        );
        let object = IdentityLoadFailure::ObjectLoad(
            crate::attach::identity_iter::LoadError::MissingProgram("p11_anchor_vma"),
        );
        assert_eq!(
            diagnosis_for_identity_load_failure(&object).stage,
            WitnessStage::ObjectLoadMissingProgram
        );
    }

    #[test]
    fn every_stage_note_is_plain_words_under_the_canonical_prefix() {
        // RED: the whole diagnosis vocabulary, pinned exactly: every
        // enriched reason keeps the canonical prefix byte-identical and
        // appends one plain-words line (no pids, paths or addresses).
        let vocabulary: &[(WitnessStage, &str)] = &[
            (
                WitnessStage::CollectionWork,
                "scoped collection deactivates the kernel proof",
            ),
            (WitnessStage::DeadlineSpent, "capture deadline already reached"),
            (
                WitnessStage::FdClone,
                "held file descriptor could not be duplicated",
            ),
            (WitnessStage::SessionLock, "witness session lock unavailable"),
            (
                WitnessStage::BtfFixMissing,
                "kernel BTF lacks the task_vma mm member",
            ),
            (
                WitnessStage::BtfNoTaskIterPidfd,
                "kernel BTF has no task-iterator pidfd support",
            ),
            (WitnessStage::BtfUnreadable, "kernel BTF is unreadable"),
            (WitnessStage::BtfParse, "kernel BTF could not be parsed"),
            (WitnessStage::ProbeDir, "no exec-capable probe directory"),
            (
                WitnessStage::ObjectLoadPermission,
                "identity BPF load refused (permission)",
            ),
            (
                WitnessStage::ObjectLoadFailed,
                "identity BPF load failed (verifier or object)",
            ),
            (
                WitnessStage::ObjectLoadMissingProgram,
                "identity object lacks a required program",
            ),
            (
                WitnessStage::ObjectLoadFdRetain,
                "verified program fd could not be retained",
            ),
            (
                WitnessStage::FunctionalProbe { stage: "scope-write" },
                "kernel identity self-test failed at stage 'scope-write'",
            ),
            (
                WitnessStage::ProbeMismatch,
                "kernel identity self-test failed its checks",
            ),
            (
                WitnessStage::CaptureDeadline,
                "capture deadline reached before the run",
            ),
            (
                WitnessStage::FdCensus,
                "file-descriptor census unavailable",
            ),
            (
                WitnessStage::AnchorOffer,
                "held file refused as witness anchor",
            ),
            (
                WitnessStage::AnchorReconcile,
                "witness anchor reservation failed",
            ),
            (
                WitnessStage::GenerationOverflow,
                "witness generation counter exhausted",
            ),
            (
                WitnessStage::ConfirmationLost,
                "kernel run lost before confirmation",
            ),
            (
                WitnessStage::TargetExited,
                "target process exited before confirmation",
            ),
            (
                WitnessStage::RangeUnproven,
                "kernel run left a refused range unproven",
            ),
            (WitnessStage::NoRefusedRange, "no refused range to prove"),
        ];
        for (stage, expected) in vocabulary {
            let diagnosis = WitnessDiagnosis::counted(*stage);
            assert_eq!(diagnosis.note(), *expected, "stage {stage:?}");
            let enriched = diagnosis.enriched_reason();
            assert!(
                enriched.starts_with(GAP_WITNESS_UNAVAILABLE),
                "the canonical prefix stays byte-identical: {enriched:?}"
            );
            assert_eq!(
                enriched,
                format!("{GAP_WITNESS_UNAVAILABLE}: {expected}"),
                "stage {stage:?}"
            );
            assert!(!enriched.contains('\n'), "one line: {enriched:?}");
        }
    }

    #[test]
    fn log_line_names_stage_and_note() {
        // RED: the internal verdict line carries the machine token plus
        // the plain-words note; joins stay bare.
        let diagnosis = WitnessDiagnosis::counted(WitnessStage::FunctionalProbe {
            stage: "scope-write",
        });
        assert_eq!(
            witness_log_line(
                WitnessVerdict::Failed(WitnessFailure::Unavailable),
                Some(diagnosis),
                3
            ),
            "p11scope: overlay-witness verdict=unavailable \
             stage=functional_probe:scope-write wall_ms=3 \
             note=\"kernel identity self-test failed at stage 'scope-write'\""
        );
        assert_eq!(
            witness_log_line(WitnessVerdict::SameFile, None, 12),
            "p11scope: overlay-witness verdict=same_file stage=- wall_ms=12"
        );
    }

    #[test]
    fn unavailable_refusal_matches_the_whole_family() {
        // RED: retries and degraded-mode arms match the canonical reason
        // and every enriched one, nothing else.
        assert!(witness_unavailable_refusal(GAP_WITNESS_UNAVAILABLE));
        assert!(witness_unavailable_refusal(
            "original_file_unproven: kernel witness unavailable: \
             scoped collection deactivates the kernel proof"
        ));
        assert!(!witness_unavailable_refusal(GAP_WITNESS_REFUSED));
        assert!(!witness_unavailable_refusal(GAP_BUDGET_EXHAUSTED));
        assert!(!witness_unavailable_refusal(GAP_ANCHOR_BINDING_FAILED));
        assert!(!witness_unavailable_refusal(""));
        assert!(!witness_unavailable_refusal(ORIGINAL_FILE_UNPROVEN));
    }

    #[test]
    fn unproven_confirmation_maps_to_confirm_stages() {
        // RED: a lost run, an exited target, an unproven range and an
        // empty range list fail closed at distinct stages.
        use crate::discovery::sweep_attribution::AttributionLoss;
        let range = (0x7f00_0000, 0x7f00_1000);
        let lost = Confirmation::Lost(AttributionLoss::MapFilesUnavailable, "gone".into());
        assert_eq!(
            stage_for_unproven_confirmation(&lost, &[range]),
            WitnessStage::ConfirmationLost
        );
        assert_eq!(
            stage_for_unproven_confirmation(&Confirmation::Exited, &[range]),
            WitnessStage::TargetExited
        );
        let mapped = BTreeMap::from([(range, RangeProof::Kernel(WITNESS_SINGLE_ANCHOR_SLOT))]);
        let gone = (0x7f00_1000, 0x7f00_2000);
        assert_eq!(
            stage_for_unproven_confirmation(&confirmed_with(mapped), &[range, gone]),
            WitnessStage::RangeUnproven
        );
        assert_eq!(
            stage_for_unproven_confirmation(&confirmed_with(BTreeMap::new()), &[]),
            WitnessStage::NoRefusedRange
        );
    }

    #[test]
    fn stored_load_diagnosis_repeats_without_reloading() {
        // RED: a failed session load remembers its stage; later queries
        // fail fast with the same diagnosis instead of retrying.
        use std::cell::Cell;
        let calls = Cell::new(0u32);
        let mut guard = WitnessSession {
            session: None,
            generation: 0,
            unavailable: None,
        };
        let stub = WitnessDiagnosis::uncounted(WitnessStage::ProbeDir);
        for _ in 0..2 {
            assert!(
                !ensure_session_loaded_with(&mut guard, || {
                    calls.set(calls.get() + 1);
                    Err(stub)
                }),
                "a failed load stays failed"
            );
        }
        assert_eq!(calls.get(), 1, "a failed load runs once, then fails fast");
        assert_eq!(
            guard.unavailable,
            Some(stub),
            "the fast path repeats the stored stage"
        );
    }

    #[test]
    fn sweep_witness_budget_exhaustion_skips_the_run() {
        let held = overlay_held();
        let mut budget = CaptureWorkBudget::default();
        let file = File::open("/dev/null").unwrap();
        let key = ObjectKey {
            device: p11scope_manifest::maps::Device { major: 8, minor: 1 },
            inode: 7_101,
        };
        let mut witness = KernelSweepWitness::new();
        witness.used = OVERLAY_SWEEP_WITNESS_QUERIES_PER_PASS;
        let (queries_before, _) = witness_stats_for_test();
        let verdict = witness.prove(
            std::process::id(),
            &file,
            &held,
            key,
            &[(0x1000_0000, 0x1000_1000)],
            &mut budget,
        );
        assert_eq!(
            verdict,
            WitnessVerdict::Failed(WitnessFailure::BudgetExhausted)
        );
        assert_eq!(witness.used(), OVERLAY_SWEEP_WITNESS_QUERIES_PER_PASS);
        let (queries_after, _) = witness_stats_for_test();
        assert_eq!(
            queries_before, queries_after,
            "an exhausted sweep budget runs no query"
        );
    }
}
