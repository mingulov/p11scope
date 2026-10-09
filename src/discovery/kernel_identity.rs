//! SPDX-License-Identifier: GPL-3.0-or-later
//! Pass-local scanner custody and anchor installation. Runtime proof selection
//! is a later slice; these owners never change default userspace collection.

use super::identity::{ExaminedObject, HeldExaminedObject, PinnedObjectId, PinnedObjects};
use super::sweep_attribution::{ReservationOwner, SegmentPolicy, Slot};
use crate::attach::identity_iter::{
    AnchorArena, Expect, RunKind, RunMode, ScopeBitmap, StrictIdentity, parse,
};
use p11scope_manifest::maps::ObjectKey;
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::os::fd::AsFd;
use std::sync::Arc;

pub(crate) const EXAMINED_ANCHOR_CAP: usize = 512;
pub(crate) const TOTAL_ANCHOR_CAP: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnchorDeny {
    FdHeadroom,
    AnchorCap,
    AnchorNotInstalled,
}

pub(crate) struct ExaminedCustody {
    pub(crate) owner: ReservationOwner,
    candidates: Vec<HeldExaminedObject>,
    callers: BTreeMap<ObjectKey, usize>,
    missing: BTreeMap<(u64, ObjectKey), AnchorDeny>,
    next_scan: u64,
    ordinal: u64,
    cap: usize,
    failed: bool,
}

impl ExaminedCustody {
    pub(crate) fn new(owner: ReservationOwner, callers: BTreeMap<ObjectKey, usize>) -> Self {
        let cap = owner.examined_capacity().min(EXAMINED_ANCHOR_CAP);
        Self {
            owner,
            candidates: Vec::new(),
            callers,
            missing: BTreeMap::new(),
            next_scan: 0,
            ordinal: 0,
            cap,
            failed: false,
        }
    }

    pub(crate) fn begin_scan(&mut self) -> u64 {
        self.next_scan += 1;
        self.next_scan
    }

    pub(crate) fn offer(&mut self, scan: u64, examined: ExaminedObject, file: File) -> bool {
        self.offer_with_census(scan, examined, file, || SegmentPolicy::try_snapshot(0, 0))
    }

    fn fail(&mut self) {
        self.failed = true;
        for held in self.candidates.drain(..) {
            self.missing
                .insert((held.scan, held.examined.key), AnchorDeny::FdHeadroom);
        }
    }

    pub(crate) fn close(&mut self) {
        self.fail();
    }

    pub(crate) fn failed(&self) -> bool {
        self.failed
    }

    fn rank(&self, key: ObjectKey, ordinal: u64) -> (Reverse<usize>, ObjectKey, u64) {
        (
            Reverse(self.callers.get(&key).copied().unwrap_or(0)),
            key,
            ordinal,
        )
    }

    fn offer_with_census(
        &mut self,
        scan: u64,
        examined: ExaminedObject,
        file: File,
        census: impl FnOnce() -> Result<SegmentPolicy, String>,
    ) -> bool {
        if self.failed || self.owner.examined_capacity() == 0 {
            self.missing
                .insert((scan, examined.key), AnchorDeny::FdHeadroom);
            return false;
        }
        let ordinal = self.ordinal;
        self.ordinal = self.ordinal.saturating_add(1);
        let replace = if self.candidates.len() >= self.cap {
            self.candidates
                .iter()
                .enumerate()
                .max_by_key(|(_, held)| self.rank(held.examined.key, held.ordinal))
                .filter(|(_, held)| {
                    self.rank(examined.key, ordinal) < self.rank(held.examined.key, held.ordinal)
                })
                .map(|(index, _)| index)
        } else {
            None
        };
        if self.candidates.len() >= self.cap && replace.is_none() {
            self.missing
                .insert((scan, examined.key), AnchorDeny::AnchorCap);
            return false;
        }
        match census() {
            Err(_) => {
                self.fail();
                self.missing
                    .insert((scan, examined.key), AnchorDeny::FdHeadroom);
                return false;
            }
            Ok(policy) if policy.headroom < 3 => {
                self.missing
                    .insert((scan, examined.key), AnchorDeny::FdHeadroom);
                return false;
            }
            Ok(_) => {}
        }
        if let Some(index) = replace {
            let removed = self.candidates.remove(index);
            self.missing
                .insert((removed.scan, removed.examined.key), AnchorDeny::AnchorCap);
            drop(removed); // Actual FD closes before acquiring its replacement lease.
        }
        let lease = match self.owner.examined() {
            Ok(lease) => lease,
            Err(_) => {
                self.missing
                    .insert((scan, examined.key), AnchorDeny::FdHeadroom);
                return false;
            }
        };
        self.candidates.push(HeldExaminedObject {
            scan,
            ordinal,
            examined,
            file,
            _lease: lease,
        });
        true
    }

    pub(crate) fn discard_scan(&mut self, scan: u64) {
        self.candidates.retain(|candidate| candidate.scan != scan);
        self.missing
            .retain(|(missing_scan, _), _| *missing_scan != scan);
    }

    #[cfg(test)]
    pub(crate) fn file_for_test(&self, scan: u64) -> Option<&File> {
        self.candidates
            .iter()
            .find(|candidate| candidate.scan == scan)
            .map(|candidate| &candidate.file)
    }

    #[cfg(test)]
    pub(crate) fn offer_for_test(
        &mut self,
        scan: u64,
        examined: ExaminedObject,
        file: File,
    ) -> bool {
        self.offer_with_census(scan, examined, file, || {
            Ok(SegmentPolicy::from_headroom(16, 0, 0))
        })
    }

    pub(crate) fn reconcile(&mut self, policy: SegmentPolicy) -> Result<(), String> {
        if let Err(error) = self.owner.reconcile(policy) {
            self.fail();
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn reconcile_census(
        &mut self,
        census: Result<SegmentPolicy, String>,
    ) -> Result<(), String> {
        match census {
            Ok(policy) if !self.failed => self.reconcile(policy),
            _ => {
                self.fail();
                Err(super::sweep_attribution::FD_CENSUS_REASON.into())
            }
        }
    }
}

enum AnchorFile<'p> {
    Pinned(&'p File),
    Examined(HeldExaminedObject),
}

impl AnchorFile<'_> {
    fn file(&self) -> &File {
        match self {
            Self::Pinned(file) => file,
            Self::Examined(held) => &held.file,
        }
    }
}

struct Candidate<'p> {
    keys: BTreeSet<ObjectKey>,
    slot: Slot,
    file: AnchorFile<'p>,
}

/// `read_run` returns completed bytes only: its descriptors close before
/// this owner can release its arena, then its scanner-opened files.
pub(crate) struct AnchorPass<'p> {
    arena: Option<AnchorArena>,
    #[cfg(test)]
    after_arena: Option<DropObserver>,
    candidates: Vec<Candidate<'p>>,
    #[cfg(test)]
    after_files: Option<DropObserver>,
    pub(crate) fallback: BTreeMap<ObjectKey, AnchorDeny>,
    pub(crate) expected: BTreeMap<ObjectKey, BTreeSet<Slot>>,
    reservations: ReservationOwner,
    binding: Option<PassBinding>,
}

#[derive(Clone)]
struct PassBinding {
    session: Arc<()>,
    generation: u64,
    arena_base: u64,
    arena_len: u64,
}

impl PassBinding {
    fn same_installation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.session, &other.session)
            && self.generation == other.generation
            && self.arena_base == other.arena_base
            && self.arena_len == other.arena_len
    }
}

/// Owns the installed arena and files while exclusively borrowing the loaded
/// object. Scope/configuration cannot be changed through another pass until
/// this guard has released its mappings and files.
pub(crate) struct InstalledAnchorPass<'s, 'p> {
    pass: Option<AnchorPass<'p>>,
    session: &'s mut IdentitySession,
}

impl InstalledAnchorPass<'_, '_> {
    pub(crate) fn read_target(
        &mut self,
        pid: Option<std::os::fd::BorrowedFd<'_>>,
        deadline: std::time::Instant,
        max_bytes: usize,
    ) -> Result<Vec<u8>, &'static str> {
        let pass = self.pass.as_mut().expect("installed guard owns its pass");
        let lease = pass
            .reservations
            .immediate()
            .transient()
            .map_err(|_| "identity target FD headroom is unavailable")?;
        let result = pass.read_run(self.session, RunKind::Target, pid, deadline, max_bytes);
        // The concrete read closes iterator/link before this lease or the
        // enclosing guard can release the arena and examined files.
        drop(lease);
        result
    }
}

impl Drop for InstalledAnchorPass<'_, '_> {
    fn drop(&mut self) {
        self.session.binding = None;
        self.session.scope.invalidate();
        // Explicit Drop keeps the exclusive session borrow alive through
        // arena -> examined File destruction, even when the guard is unused.
        drop(self.pass.take());
    }
}

#[cfg(test)]
struct DropObserver(Option<Box<dyn FnOnce()>>);
#[cfg(test)]
impl Drop for DropObserver {
    fn drop(&mut self) {
        if let Some(observe) = self.0.take() {
            observe();
        }
    }
}

impl<'p> AnchorPass<'p> {
    pub(crate) fn prepare(
        pins: &'p PinnedObjects,
        admitted: impl IntoIterator<Item = (ObjectKey, PinnedObjectId)>,
        custody: ExaminedCustody,
    ) -> Self {
        Self::prepare_limits(
            pins,
            admitted,
            custody,
            EXAMINED_ANCHOR_CAP,
            TOTAL_ANCHOR_CAP,
        )
    }

    fn prepare_limits(
        pins: &'p PinnedObjects,
        admitted: impl IntoIterator<Item = (ObjectKey, PinnedObjectId)>,
        mut custody: ExaminedCustody,
        examined_cap: usize,
        total_cap: usize,
    ) -> Self {
        let mut pass = Self {
            arena: None,
            #[cfg(test)]
            after_arena: None,
            candidates: Vec::new(),
            #[cfg(test)]
            after_files: None,
            fallback: custody
                .missing
                .into_iter()
                .map(|((_, key), reason)| (key, reason))
                .collect(),
            expected: BTreeMap::new(),
            reservations: custody.owner.clone(),
            binding: None,
        };
        let mut admitted_by_id: BTreeMap<PinnedObjectId, BTreeSet<ObjectKey>> = BTreeMap::new();
        for (key, id) in admitted {
            admitted_by_id.entry(id).or_default().insert(key);
        }
        for (id, keys) in admitted_by_id {
            let Some(file) = pins.file_for(id) else {
                for key in keys {
                    pass.fallback.insert(key, AnchorDeny::AnchorNotInstalled);
                }
                continue;
            };
            if pass.candidates.len() >= total_cap.min(TOTAL_ANCHOR_CAP) {
                for key in keys {
                    pass.fallback.insert(key, AnchorDeny::AnchorCap);
                }
                continue;
            }
            pass.candidates.push(Candidate {
                keys,
                slot: Slot(pass.candidates.len() as u32),
                file: AnchorFile::Pinned(file),
            });
        }
        let callers = &custody.callers;
        custody.candidates.sort_by_key(|held| {
            (
                Reverse(callers.get(&held.examined.key).copied().unwrap_or(0)),
                held.examined.key,
                held.ordinal,
            )
        });
        for (index, held) in custody.candidates.into_iter().enumerate() {
            if index >= examined_cap.min(EXAMINED_ANCHOR_CAP)
                || pass.candidates.len() >= total_cap.min(TOTAL_ANCHOR_CAP)
            {
                pass.fallback
                    .insert(held.examined.key, AnchorDeny::AnchorCap);
                continue;
            }
            pass.candidates.push(Candidate {
                keys: BTreeSet::from([held.examined.key]),
                slot: Slot(pass.candidates.len() as u32),
                file: AnchorFile::Examined(held),
            });
        }
        if pass.candidates.is_empty() {
            return pass;
        }
        let arena = match AnchorArena::reserve(pass.candidates.len() as u32) {
            Ok(arena) => arena,
            Err(_) => {
                for candidate in &pass.candidates {
                    for key in &candidate.keys {
                        pass.fallback.insert(*key, AnchorDeny::AnchorNotInstalled);
                    }
                }
                pass.candidates.clear();
                return pass;
            }
        };
        pass.candidates.retain(|candidate| {
            let file = candidate.file.file();
            let mapped = file.metadata().is_ok_and(|meta| meta.len() > 0)
                && arena.map_slot(candidate.slot.0, file.as_fd()).is_ok();
            if !mapped {
                for key in &candidate.keys {
                    pass.fallback.insert(*key, AnchorDeny::AnchorNotInstalled);
                }
            }
            mapped
        });
        pass.arena = Some(arena);
        pass
    }

    fn accept_anchor_run(&mut self, bytes: &[u8], generation: u64) -> Result<(), String> {
        self.expected.clear();
        let run = parse(
            bytes,
            &Expect {
                generation,
                slots: self.arena.as_ref().map_or(0, |arena| {
                    (arena.len() / crate::attach::identity_iter::ANCHOR_STRIDE) as u32
                }),
                scope: &BTreeSet::from([std::process::id()]),
                mode: RunMode::PerPid,
                run: RunKind::Anchor,
            },
        )
        .map_err(|_| "anchor installation stream is invalid".to_string())?;
        for candidate in &self.candidates {
            let root = match run.anchors.get(&candidate.slot.0) {
                Some(crate::attach::identity_iter::AnchorOutcome::Ok) => candidate.slot,
                Some(crate::attach::identity_iter::AnchorOutcome::Dup(root)) => Slot(*root),
                _ => {
                    for key in &candidate.keys {
                        self.fallback.insert(*key, AnchorDeny::AnchorNotInstalled);
                    }
                    continue;
                }
            };
            // Parser aliases are valid only relative to installed OK records.
            // A failed userspace mapping may leave a reserved slot gap: it
            // cannot supply an alias root even if an injected stream says OK.
            if !self
                .candidates
                .iter()
                .any(|installed| installed.slot == root)
            {
                for key in &candidate.keys {
                    self.fallback.insert(*key, AnchorDeny::AnchorNotInstalled);
                }
                continue;
            }
            for key in &candidate.keys {
                self.expected.entry(*key).or_default().insert(root);
            }
        }
        self.expected
            .retain(|key, _| !self.fallback.contains_key(key));
        Ok(())
    }

    fn read_run(
        &mut self,
        session: &IdentitySession,
        run: RunKind,
        pid: Option<std::os::fd::BorrowedFd<'_>>,
        deadline: std::time::Instant,
        max_bytes: usize,
    ) -> Result<Vec<u8>, &'static str> {
        let Some(binding) = &self.binding else {
            return Err("identity pass is not installed");
        };
        let owned = session.binding.as_ref().is_some_and(|installed| {
            binding.same_installation(installed)
                && Arc::ptr_eq(&binding.session, &session.token)
                && binding.generation == session.generation
                && self.arena.as_ref().is_some_and(|arena| {
                    arena.base() == binding.arena_base && arena.len() == binding.arena_len
                })
        });
        if !owned {
            return Err("identity pass installation is unavailable");
        }
        if !session.scope.ready() {
            return Err("identity scope is unavailable");
        }
        session.read(run, pid, deadline, max_bytes)
    }

    #[cfg(test)]
    fn read_fixture_run(
        &mut self,
        iter: std::os::fd::OwnedFd,
        link: std::os::fd::OwnedFd,
        deadline: std::time::Instant,
        max_bytes: usize,
    ) -> Result<Vec<u8>, crate::attach::identity_iter::ReadError> {
        crate::attach::identity_iter::consume_owned_run(iter, link, deadline, max_bytes)
    }
}

/// The scope tracker belongs to this one fresh object; a failed replacement
/// cannot be bypassed by calling its iterator with an unrelated ready tracker.
pub(crate) struct IdentitySession {
    object: SessionObject,
    scope: ScopeBitmap,
    generation: u64,
    token: Arc<()>,
    binding: Option<PassBinding>,
}

enum SessionObject {
    Kernel(StrictIdentity),
    #[cfg(test)]
    Fixture {
        _object: File,
        anchor: Vec<u8>,
        target: Vec<u8>,
        config: Option<crate::attach::identity_iter::IdentityConfig>,
        fail_config: bool,
        reads: std::cell::Cell<usize>,
    },
}

fn probe_succeeded(report: &crate::attach::identity_iter::FunctionalProbeReport) -> bool {
    use crate::attach::identity_iter::{AnchorOutcome, TargetVerdict};
    report.anchor_outcomes == [(0, AnchorOutcome::Ok), (1, AnchorOutcome::Ok)]
        && report.hardlink_verdict == TargetVerdict::Slot(0)
        && report.second_verdict == TargetVerdict::Slot(1)
        && report.copy_verdict == TargetVerdict::Unmatched
        && report.pids_seen == [report.child_pid]
        && report.demoted_pids.is_empty()
        && report.stale_unmatched
}

impl IdentitySession {
    #[cfg(test)]
    fn install_unowned_for_test<'p>(
        &mut self,
        pass: AnchorPass<'p>,
        generation: u64,
        deadline: std::time::Instant,
    ) -> Result<AnchorPass<'p>, &'static str> {
        self.install_pass(pass, generation, deadline)
    }

    pub(crate) fn probe_and_load(
        btf: &aya::Btf,
        dir: &std::path::Path,
    ) -> Result<Self, &'static str> {
        let loaded = probe_then_fresh(
            || {
                crate::attach::identity_iter::load_identity_object_strict(btf)
                    .map_err(|_| "identity object load failed")
            },
            |loaded| {
                let report = crate::attach::identity_iter::run_functional_probe(dir, loaded, 1)
                    .map_err(|_| "identity functional probe failed")?;
                if probe_succeeded(&report) {
                    Ok(())
                } else {
                    Err("identity functional probe failed")
                }
            },
        )?;
        Ok(Self {
            object: SessionObject::Kernel(loaded),
            scope: ScopeBitmap::default(),
            generation: 0,
            token: Arc::new(()),
            binding: None,
        })
    }

    pub(crate) fn replace_scope(&mut self, tgids: &[u32]) -> Result<(), &'static str> {
        self.binding = None;
        match &mut self.object {
            SessionObject::Kernel(loaded) => self
                .scope
                .replace(&mut loaded.ebpf, tgids)
                .map_err(|_| "identity scope is unavailable"),
            #[cfg(test)]
            SessionObject::Fixture { .. } => self.scope.fixture_replace(tgids),
        }
    }

    fn configure(
        &mut self,
        config: crate::attach::identity_iter::IdentityConfig,
    ) -> Result<(), &'static str> {
        match &mut self.object {
            SessionObject::Kernel(loaded) => {
                crate::attach::identity_iter::write_identity_config(&mut loaded.ebpf, &config)
                    .map_err(|_| "identity anchor configuration failed")
            }
            #[cfg(test)]
            SessionObject::Fixture {
                config: installed,
                fail_config,
                ..
            } => {
                if *fail_config {
                    return Err("injected configuration failure");
                }
                *installed = Some(config);
                Ok(())
            }
        }
    }

    fn read(
        &self,
        run: RunKind,
        pid: Option<std::os::fd::BorrowedFd<'_>>,
        deadline: std::time::Instant,
        max_bytes: usize,
    ) -> Result<Vec<u8>, &'static str> {
        match &self.object {
            SessionObject::Kernel(loaded) => {
                let program = match run {
                    RunKind::Anchor => &loaded.anchor_fd,
                    RunKind::Target => &loaded.target_fd,
                };
                crate::attach::identity_iter::attach_and_read_run(
                    program.as_fd(),
                    pid,
                    deadline,
                    max_bytes,
                )
                .map_err(|_| "identity iterator run failed")
            }
            #[cfg(test)]
            SessionObject::Fixture {
                anchor,
                target,
                reads,
                ..
            } => {
                use std::os::unix::fs::FileExt;
                reads.set(reads.get() + 1);
                let file = tempfile::tempfile().unwrap();
                file.write_at(
                    match run {
                        RunKind::Anchor => anchor,
                        RunKind::Target => target,
                    },
                    0,
                )
                .unwrap();
                crate::attach::identity_iter::consume_owned_run(
                    file.into(),
                    tempfile::tempfile().unwrap().into(),
                    deadline,
                    max_bytes,
                )
                .map_err(|_| "identity iterator run failed")
            }
        }
    }

    /// Install only this pass's observer anchors. Target-range proof belongs
    /// to D3c. A generation is spent before I/O so a failed pass cannot reuse it.
    pub(crate) fn install_anchors<'s, 'p>(
        &'s mut self,
        pass: AnchorPass<'p>,
        generation: u64,
        deadline: std::time::Instant,
    ) -> Result<InstalledAnchorPass<'s, 'p>, &'static str> {
        let pass = self.install_pass(pass, generation, deadline)?;
        Ok(InstalledAnchorPass {
            pass: Some(pass),
            session: self,
        })
    }

    fn install_pass<'p>(
        &mut self,
        pass: AnchorPass<'p>,
        generation: u64,
        deadline: std::time::Instant,
    ) -> Result<AnchorPass<'p>, &'static str> {
        self.binding = None;
        self.scope.invalidate();
        let result = self.install_pass_inner(pass, generation, deadline);
        if result.is_err() {
            self.binding = None;
            self.scope.invalidate();
        }
        result
    }

    fn install_pass_inner<'p>(
        &mut self,
        mut pass: AnchorPass<'p>,
        generation: u64,
        deadline: std::time::Instant,
    ) -> Result<AnchorPass<'p>, &'static str> {
        pass.expected.clear();
        if generation <= self.generation || generation >= u64::from(u32::MAX) {
            return Err("identity generation is unavailable");
        }
        self.generation = generation;
        let Some(arena) = pass.arena.as_ref() else {
            return Err("identity anchor arena is unavailable");
        };
        let slots = (arena.len() / crate::attach::identity_iter::ANCHOR_STRIDE) as u32;
        let config = arena.config(generation, slots, std::process::id());
        self.replace_scope(&[std::process::id()])?;
        self.configure(config)?;
        let binding = PassBinding {
            session: self.token.clone(),
            generation,
            arena_base: arena.base(),
            arena_len: arena.len(),
        };
        pass.binding = Some(binding.clone());
        self.binding = Some(binding);
        let pid_lease = pass
            .reservations
            .immediate()
            .pin()
            .map_err(|_| "identity anchor FD headroom is unavailable")?;
        let pid = crate::attach::identity_iter::open_pidfd(std::process::id())
            .map_err(|_| "identity anchor observer is unavailable")?;
        let run_lease = pass
            .reservations
            .immediate()
            .transient()
            .map_err(|_| "identity anchor FD headroom is unavailable")?;
        let result = pass.read_run(
            self,
            RunKind::Anchor,
            Some(pid.as_fd()),
            deadline,
            (slots as usize + 1) * crate::attach::identity_iter::RECORD_LEN,
        );
        drop(run_lease);
        drop(pid);
        drop(pid_lease);
        let bytes = result?;
        pass.accept_anchor_run(&bytes, generation)
            .map_err(|_| "identity anchor installation failed")?;
        Ok(pass)
    }
}

/// The probe mutates scope/config/generation. Production requires a distinct
/// fresh strict-loaded object after the complete probe owner has been dropped.
fn probe_then_fresh<L, E>(
    mut load: impl FnMut() -> Result<L, E>,
    probe: impl FnOnce(&mut L) -> Result<(), E>,
) -> Result<L, E> {
    let mut loaded = load()?;
    probe(&mut loaded)?;
    drop(loaded);
    load()
}

#[cfg(test)]
#[path = "kernel_identity_tests.rs"]
mod tests;
