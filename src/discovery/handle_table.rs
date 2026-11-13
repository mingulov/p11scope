//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! One capture-owned library-handle table: every retained library fd is
//! filed here through the single `acquire()`, so `held <= len() <= cap`
//! holds by construction instead of by per-site convention.

use crate::discovery::identity::{EntryMeta, FileIdentity, MappedFile, Pin, pin_of};
use p11scope_manifest::maps::ObjectKey;
use std::collections::BTreeMap;
use std::ops::Deref;
use std::sync::{Arc, Weak};

/// Monotonic row number: the filing identity of one table row.
pub(crate) type RowId = u64;
/// The row a handle was filed under; untabled handles carry `RowId::MAX`.
pub(crate) type HandleId = RowId;

/// The proven file identity one row stands for: the maps key that routed
/// the pin, the held fd's own fstat identity, the `(ino, size, ctime)`
/// pin, the whole-file digest and the prove-time inode-uniqueness proof.
/// Maps keys never index the table alone: Btrfs snapshot twins and
/// copy-up pairs share maps keys across distinct kernel files.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ProvenKey {
    maps: ObjectKey,
    file: FileIdentity,
    pin: Pin,
    /// Empty iff unhashed; unhashed entries never share.
    sha256: String,
    /// `file_inodes_are_unique` at prove time.
    unique: bool,
    /// Nonzero iff non-dedupable; never matches a lookup.
    nonce: u64,
}

/// One filed file: a weak share of the resident fd plus the lender
/// predicates' inputs. Rows release when their last handle drops; a
/// memory-only [`HandleTable::prune`] reaps the dead ones.
#[derive(Debug)]
pub(crate) struct Row {
    file: Weak<std::fs::File>,
    mapped: Option<MappedFile>,
    pin: Pin,
    overlay: bool,
    collapsed: bool,
}

impl Row {
    /// The resident's reusable mapped proof: the `reusable_mapped_file`
    /// lender half over this row's own pin. Fstat-only, no reads.
    fn reusable_mapped(&self, live: &std::fs::File) -> Option<MappedFile> {
        self.mapped.filter(|mapped| {
            !self.overlay
                && !self.collapsed
                && mapped.may_retain()
                && pin_of(live).is_ok_and(|current| current == self.pin)
        })
    }
}

/// A filed library handle: the row it was filed under plus its share of
/// the resident fd. Cloning shares; the fd closes with the last share.
#[derive(Debug, Clone)]
pub(crate) struct TableHandle {
    id: HandleId,
    file: Arc<std::fs::File>,
}

impl TableHandle {
    /// A handle filed under no row (migration only; deleted in Task 6).
    pub(crate) fn untracked(file: Arc<std::fs::File>) -> Self {
        Self {
            id: RowId::MAX,
            file,
        }
    }

    /// A fixture handle filed under no row.
    #[cfg(test)]
    pub(crate) fn for_test(file: Arc<std::fs::File>) -> Self {
        Self {
            id: RowId::MAX,
            file,
        }
    }

    pub(crate) fn id(&self) -> HandleId {
        self.id
    }

    pub(crate) fn arc(&self) -> &Arc<std::fs::File> {
        &self.file
    }

    /// Whether both handles share one open file description.
    pub(crate) fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.file, &other.file)
    }
}

impl Deref for TableHandle {
    type Target = std::fs::File;

    fn deref(&self) -> &Self::Target {
        &self.file
    }
}

impl AsRef<std::fs::File> for TableHandle {
    fn as_ref(&self) -> &std::fs::File {
        &self.file
    }
}

/// One filed pin: its handle, its mapped proof (its own, or the
/// resident's when it had none) and whether it filed a new row.
#[derive(Debug)]
pub(crate) struct Held {
    pub(crate) handle: TableHandle,
    pub(crate) mapped: Option<MappedFile>,
    // Read by the Task-1 reserve debit; unit tests until then.
    #[allow(dead_code)]
    pub(crate) inserted: bool,
}

impl Held {
    /// A pin filed under no row (migration only; deleted in Task 6).
    pub(crate) fn untracked(file: Arc<std::fs::File>, mapped: Option<MappedFile>) -> Self {
        Self {
            handle: TableHandle::untracked(file),
            mapped,
            inserted: false,
        }
    }
}

/// Why a refusal waits where it does: the site class whose gap vocabulary
/// the caller files. Admission scans map to the initial/live budget tails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
// Initial/Live are constructed by the Task-1 admission paths; Trusted
// and Learned follow in Tasks 3-4, when this allow goes away.
#[allow(dead_code)]
pub(crate) enum DeferredReason {
    Initial,
    Live,
    Trusted,
    Learned,
}

/// The single acquire step's outcome: filed, or refused with its reason.
/// The pin loops match this and record their fixed gap vocabulary; the
/// carried reason stays an origin tag for debugging.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum AcquireOutcome {
    Held(Held),
    Deferred(DeferredReason),
}

#[cfg(test)]
impl AcquireOutcome {
    pub(crate) fn held(self, message: &str) -> Held {
        match self {
            Self::Held(held) => held,
            Self::Deferred(reason) => panic!("{message}: deferred with {reason:?}"),
        }
    }
}

/// One memory-only reap: rows reaped and dead rows left pending.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PruneStats {
    pub(crate) reaped: usize,
    pub(crate) pending: usize,
}

/// The table's counters: admissions, shares, refusals, reaps, live rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TableStats {
    pub(crate) admits: u64,
    pub(crate) shares: u64,
    pub(crate) defers: u64,
    pub(crate) prunes: u64,
    pub(crate) len: usize,
}

/// Where the pin path files one worker-proven pin: a table row
/// (count-only or refusing), no row, or a probe-local scratch dropped
/// at return.
pub(crate) enum Filing<'a> {
    /// Count-only filing (Phase 0 migration): shares like `acquire()`
    /// but never refuses. Converted row groups use `Acquire` instead;
    /// deleted once every site acquires.
    Adopt(&'a mut HandleTable),
    /// The single acquire step with the caller's refusal reason. The
    /// pin loops record the refusal as waits; no site drops a pin.
    Acquire(&'a mut HandleTable, DeferredReason),
    Untracked,
    /// Wired in Task 4 (the probationary probe files no rows at all).
    #[allow(dead_code)]
    Scratch,
}

/// The capture-owned handle table. Each acquisition opens a temporary
/// handle (covered by the 128-fd reserve), proves it with the unchanged
/// worker, then files it here: a proven duplicate shares the resident
/// `Arc`; a new file inserts while `len < cap`; a full table refuses
/// with the named deferral gap after one prune-then-retry.
#[derive(Debug)]
pub(crate) struct HandleTable {
    rows: BTreeMap<(ProvenKey, RowId), Row>,
    /// Live rows per maps key: the pre-open fast path's routing index.
    maps_live: BTreeMap<ObjectKey, usize>,
    cap: usize,
    next_row: RowId,
    next_nonce: u64,
    admits: u64,
    shares: u64,
    defers: u64,
    prunes: u64,
}

impl HandleTable {
    pub(crate) fn new(cap: usize) -> Self {
        Self {
            rows: BTreeMap::new(),
            maps_live: BTreeMap::new(),
            cap,
            next_row: 0,
            next_nonce: 1,
            admits: 0,
            shares: 0,
            defers: 0,
            prunes: 0,
        }
    }

    /// The single acquire step: file one worker-proven pin. A proven
    /// duplicate shares the resident handle; a new file inserts while
    /// `len < cap`; past the cap the table prunes once, retries once,
    /// then refuses with the caller's reason. Fstat-only I/O, no reads.
    pub(crate) fn acquire(
        &mut self,
        file: std::fs::File,
        meta: &EntryMeta,
        reason: DeferredReason,
    ) -> AcquireOutcome {
        self.file_or_refuse(Arc::new(file), meta, true, reason)
    }

    /// Count-only filing of a worker-proven pin (Phase 0 migration):
    /// shares like [`HandleTable::acquire`] but never refuses — inserts
    /// even past the cap, so `held <= len() <= cap` holds only from
    /// Task 6, once every site acquires.
    pub(crate) fn adopt(&mut self, file: std::fs::File, meta: &EntryMeta) -> Held {
        self.adopt_shared(Arc::new(file), meta)
    }

    /// Count-only filing of an already-shared handle (C4 re-file): same
    /// proven-key routing as [`HandleTable::adopt`], over an `Arc` the
    /// caller already holds instead of a fresh open.
    pub(crate) fn adopt_shared(&mut self, file: Arc<std::fs::File>, meta: &EntryMeta) -> Held {
        match self.file_or_refuse(file, meta, false, DeferredReason::Live) {
            AcquireOutcome::Held(held) => held,
            AcquireOutcome::Deferred(_) => unreachable!("count-only adopt never refuses"),
        }
    }

    /// Shared filing core: proven-key lookup, then insert — or, when
    /// `refuse`, prune-then-retry once and defer with `reason`.
    fn file_or_refuse(
        &mut self,
        file: Arc<std::fs::File>,
        meta: &EntryMeta,
        refuse: bool,
        reason: DeferredReason,
    ) -> AcquireOutcome {
        let (key, dedupable) = self.derive_key(meta, &file);
        if dedupable && let Some((id, resident, resident_mapped)) = self.lookup_share(&key, meta) {
            self.shares = self.shares.saturating_add(1);
            return AcquireOutcome::Held(Held {
                handle: TableHandle { id, file: resident },
                mapped: meta.mapped.or(resident_mapped),
                inserted: false,
            });
        }
        if refuse && crate::fd_budget::library_handle_budget_exhausted(self.len(), self.cap) {
            self.prune(usize::MAX);
            if crate::fd_budget::library_handle_budget_exhausted(self.len(), self.cap) {
                self.defers = self.defers.saturating_add(1);
                return AcquireOutcome::Deferred(reason);
            }
        }
        AcquireOutcome::Held(self.insert_row(key, file, meta))
    }

    /// Test-only filing of an existing handle: dedups by `Arc` pointer,
    /// one row per distinct open file. For the engine test helper only.
    #[cfg(test)]
    pub(crate) fn adopt_existing(&mut self, existing: &TableHandle) -> Held {
        for ((_, id), row) in &self.rows {
            if row
                .file
                .upgrade()
                .is_some_and(|live| Arc::ptr_eq(&live, existing.arc()))
            {
                self.shares = self.shares.saturating_add(1);
                return Held {
                    handle: TableHandle {
                        id: *id,
                        file: existing.arc().clone(),
                    },
                    mapped: row.mapped,
                    inserted: false,
                };
            }
        }
        // A bare handle carries no proven meta: file it under a fresh
        // nonce key that never matches a lookup, like any non-dedupable.
        let key = self.nonce_key_for(existing.arc());
        let id = self.alloc_row();
        self.maps_live
            .entry(key.maps)
            .and_modify(|live| *live = live.saturating_add(1))
            .or_insert(1);
        self.rows.insert(
            (key, id),
            Row {
                file: Arc::downgrade(existing.arc()),
                mapped: None,
                pin: crate::discovery::identity::pin_of(existing.arc())
                    .expect("adopt_existing stats a live handle"),
                overlay: false,
                collapsed: false,
            },
        );
        self.admits = self.admits.saturating_add(1);
        Held {
            handle: TableHandle {
                id,
                file: existing.arc().clone(),
            },
            mapped: None,
            inserted: true,
        }
    }

    /// Memory-only reap of rows whose `Weak` no longer upgrades. No
    /// `close(2)`: fds close with their last `TableHandle` drop. Bounded
    /// to `max_rows` reaps per call; the remainder is an exact pending
    /// count, so callers loop to quiescence.
    pub(crate) fn prune(&mut self, max_rows: usize) -> PruneStats {
        let mut reaped = 0usize;
        let mut pending = 0usize;
        let mut dead = Vec::new();
        for (key, row) in &self.rows {
            if row.file.upgrade().is_none() {
                if reaped < max_rows {
                    reaped += 1;
                    dead.push(key.clone());
                } else {
                    pending += 1;
                }
            }
        }
        for key in dead {
            self.rows.remove(&key);
            if let Some(live) = self.maps_live.get_mut(&key.0.maps) {
                *live = live.saturating_sub(1);
                if *live == 0 {
                    self.maps_live.remove(&key.0.maps);
                }
            }
        }
        self.prunes = self.prunes.saturating_add(reaped as u64);
        PruneStats { reaped, pending }
    }

    /// Live rows: at least the live fds, at most the cap from Task 6.
    pub(crate) fn len(&self) -> usize {
        self.rows.len()
    }

    /// The concurrent-handle cap this table enforces.
    pub(crate) fn cap(&self) -> usize {
        self.cap
    }

    /// Test-only cap override (the `library_handle_cap_for_test` seam,
    /// repointed at the table).
    #[cfg(test)]
    pub(crate) fn set_cap(&mut self, cap: usize) {
        self.cap = cap;
    }

    /// The table's counters: the admission loops debit the fd reserve
    /// from `admits`; `-v`/timing diagnostics surface the rest (Task 6).
    pub(crate) fn stats(&self) -> TableStats {
        TableStats {
            admits: self.admits,
            shares: self.shares,
            defers: self.defers,
            prunes: self.prunes,
            len: self.rows.len(),
        }
    }

    /// The cheap pre-open fast path: when full with no row under the
    /// borrower's maps key, defer without opening. A fail-closed
    /// refusal, never an admission prediction. Wired in Task 1.
    #[allow(dead_code)]
    pub(crate) fn preopen_defers(&self, maps: &ObjectKey) -> bool {
        // Every prior acquire already filed or deferred, so nothing is
        // speculative at this point: `scan_new` is 0 and the kept
        // predicate below is exactly the room check.
        !self.maps_live.contains_key(maps)
            && crate::fd_budget::library_handle_budget_defers_next_new(self.len(), 0, self.cap)
    }

    /// Route one proven pin: its table key plus whether it may share.
    /// Empty-digest, non-unique, `pre_copy_up` and `collapsed` pins
    /// take a fresh nonzero nonce, skip the lookup and insert-or-defer
    /// on their own row. An unreadable fstat fails closed the same way.
    fn derive_key(&mut self, meta: &EntryMeta, file: &std::fs::File) -> (ProvenKey, bool) {
        use std::os::unix::fs::MetadataExt as _;
        let identity = file.metadata().ok().map(|metadata| FileIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        });
        let dedupable = identity.is_some()
            && !meta.sha256.is_empty()
            && meta.unique
            && !meta.pre_copy_up
            && !meta.collapsed;
        let nonce = if dedupable {
            0
        } else {
            let nonce = self.next_nonce;
            self.next_nonce = self.next_nonce.wrapping_add(1).max(1);
            nonce
        };
        let key = ProvenKey {
            maps: meta.raw.key,
            file: identity.unwrap_or(FileIdentity {
                dev: u64::MAX,
                ino: u64::MAX,
            }),
            pin: meta.pin,
            sha256: meta.sha256.clone(),
            unique: meta.unique,
            nonce,
        };
        (key, dedupable)
    }

    /// The first resident under `key` (in `RowId` order) passing the
    /// real lender predicates: a live share, a reusable mapped proof
    /// and a maps key that is this file's identity.
    fn lookup_share(
        &self,
        key: &ProvenKey,
        meta: &EntryMeta,
    ) -> Option<(RowId, Arc<std::fs::File>, Option<MappedFile>)> {
        let from = (key.clone(), 0);
        let to = (key.clone(), RowId::MAX);
        self.rows.range(from..=to).find_map(|((_, id), row)| {
            let live = row.file.upgrade()?;
            let lender = row.reusable_mapped(&live)?;
            lender
                .key_is_identity(meta.raw.key)
                .then_some((*id, live, row.mapped))
        })
    }

    /// File one pin on its own new row.
    fn insert_row(&mut self, key: ProvenKey, file: Arc<std::fs::File>, meta: &EntryMeta) -> Held {
        let id = self.alloc_row();
        self.maps_live
            .entry(key.maps)
            .and_modify(|live| *live = live.saturating_add(1))
            .or_insert(1);
        self.rows.insert(
            (key, id),
            Row {
                file: Arc::downgrade(&file),
                mapped: meta.mapped,
                pin: meta.pin,
                overlay: meta.overlay,
                collapsed: meta.collapsed,
            },
        );
        self.admits = self.admits.saturating_add(1);
        Held {
            handle: TableHandle { id, file },
            mapped: meta.mapped,
            inserted: true,
        }
    }

    fn alloc_row(&mut self) -> RowId {
        let id = self.next_row;
        // `RowId::MAX` is the untabled marker: no row ever takes it.
        self.next_row = self
            .next_row
            .checked_add(1)
            .filter(|next| *next != RowId::MAX)
            .expect("handle-table row id overflow");
        id
    }

    /// A fresh nonce key for a bare handle (test-only filing): the live
    /// fstat identity under a zero maps key, never matching a lookup.
    #[cfg(test)]
    fn nonce_key_for(&mut self, file: &Arc<std::fs::File>) -> ProvenKey {
        use std::os::unix::fs::MetadataExt as _;
        let identity = file.metadata().ok().map(|metadata| FileIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
        });
        let nonce = self.next_nonce;
        self.next_nonce = self.next_nonce.wrapping_add(1).max(1);
        ProvenKey {
            maps: ObjectKey {
                device: p11scope_manifest::maps::Device { major: 0, minor: 0 },
                inode: 0,
            },
            file: identity.unwrap_or(FileIdentity {
                dev: u64::MAX,
                ino: u64::MAX,
            }),
            pin: crate::discovery::identity::pin_of(file)
                .expect("adopt_existing stats a live handle"),
            sha256: String::new(),
            unique: false,
            nonce,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::identity::{FileIdentity, MappedFile, ProvedEntry};
    use p11scope_manifest::maps::{Device, ObjectKey};
    use std::os::unix::fs::MetadataExt as _;

    fn fixture_bytes(name: &str, bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        (dir, path)
    }

    fn maps_key_for(path: &std::path::Path) -> ObjectKey {
        let metadata = std::fs::metadata(path).unwrap();
        ObjectKey {
            device: Device {
                major: u64::from(libc::major(metadata.dev())),
                minor: u64::from(libc::minor(metadata.dev())),
            },
            inode: metadata.ino(),
        }
    }

    fn mapped_proof_for(key: ObjectKey) -> MappedFile {
        let device = libc::makedev(key.device.major as u32, key.device.minor as u32);
        MappedFile {
            identity: FileIdentity {
                dev: device,
                ino: key.inode,
            },
            fs_magic: Some(0xef53),
        }
    }

    fn proved(
        path: &std::path::Path,
        maps: ObjectKey,
        sha256: &str,
        mapped: Option<MappedFile>,
    ) -> ProvedEntry {
        ProvedEntry::for_test(std::fs::File::open(path).unwrap(), maps, sha256, mapped)
    }

    fn acquire(
        table: &mut HandleTable,
        proved: ProvedEntry,
        reason: DeferredReason,
    ) -> AcquireOutcome {
        let ProvedEntry { file, meta } = proved;
        table.acquire(file, &meta, reason)
    }

    fn adopt(table: &mut HandleTable, proved: ProvedEntry) -> Held {
        let ProvedEntry { file, meta } = proved;
        table.adopt(file, &meta)
    }

    #[test]
    fn table_admits_two_distinct_files_then_defers_third() {
        let (_d1, first) = fixture_bytes("first.so", b"first-bytes");
        let (_d2, second) = fixture_bytes("second.so", b"second-bytes");
        let (_d3, third) = fixture_bytes("third.so", b"third-bytes");
        let mut table = HandleTable::new(2);
        let first_held = acquire(
            &mut table,
            proved(&first, maps_key_for(&first), "aa", None),
            DeferredReason::Live,
        )
        .held("the first distinct file admits");
        assert!(first_held.inserted);
        let second_held = acquire(
            &mut table,
            proved(&second, maps_key_for(&second), "bb", None),
            DeferredReason::Live,
        )
        .held("the second distinct file admits");
        assert!(second_held.inserted);
        assert_eq!(table.len(), 2);
        assert!(matches!(
            acquire(
                &mut table,
                proved(&third, maps_key_for(&third), "cc", None),
                DeferredReason::Live,
            ),
            AcquireOutcome::Deferred(DeferredReason::Live)
        ));
        assert_eq!(table.len(), 2);
        assert_eq!(table.stats().defers, 1);
    }

    #[test]
    fn preopen_fast_path_defers_without_opening_when_full() {
        let (_dir, path) = fixture_bytes("lib.so", b"shared-bytes");
        let key = maps_key_for(&path);
        let mut table = HandleTable::new(1);
        assert!(!table.preopen_defers(&key), "headroom never defers");
        let _held = acquire(
            &mut table,
            proved(&path, key, "aa", None),
            DeferredReason::Live,
        )
        .held("the row admits");
        assert_eq!(table.len(), 1);
        let other = ObjectKey {
            device: Device { major: 9, minor: 9 },
            inode: 4242,
        };
        assert!(
            table.preopen_defers(&other),
            "a full table with no row under the key defers before opening"
        );
        assert!(
            !table.preopen_defers(&key),
            "a routed key may still share; only the acquire decides"
        );
    }

    #[test]
    fn shared_acquire_carries_resident_mapped_and_relends() {
        let (_dir, path) = fixture_bytes("lib.so", b"shared-bytes");
        let key = maps_key_for(&path);
        let mapped = mapped_proof_for(key);
        let mut table = HandleTable::new(2);
        let lender = acquire(
            &mut table,
            proved(&path, key, "aa", Some(mapped)),
            DeferredReason::Live,
        )
        .held("the lender admits");
        assert!(lender.inserted);
        let borrower = acquire(
            &mut table,
            proved(&path, key, "aa", None),
            DeferredReason::Live,
        )
        .held("the same file shares");
        assert!(!borrower.inserted, "a share files no new row");
        assert_eq!(table.len(), 1);
        assert_eq!(borrower.mapped, Some(mapped));
        assert!(
            std::sync::Arc::ptr_eq(&lender.handle.file, &borrower.handle.file),
            "the borrower shares the resident fd"
        );
        drop(lender);
        let stats = table.prune(usize::MAX);
        assert_eq!((stats.reaped, stats.pending), (0, 0));
        assert_eq!(table.len(), 1, "the borrower's share keeps the row live");
        let third = acquire(
            &mut table,
            proved(&path, key, "aa", None),
            DeferredReason::Live,
        )
        .held("the borrower entry re-lends");
        assert!(!third.inserted);
        assert_eq!(third.mapped, Some(mapped));
    }

    #[test]
    fn prune_reaps_only_dead_rows_and_reports_pending() {
        let (_d1, first) = fixture_bytes("first.so", b"first-bytes");
        let (_d2, second) = fixture_bytes("second.so", b"second-bytes");
        let mut table = HandleTable::new(2);
        let _kept = acquire(
            &mut table,
            proved(&first, maps_key_for(&first), "aa", None),
            DeferredReason::Live,
        )
        .held("first admits");
        let dropped = acquire(
            &mut table,
            proved(&second, maps_key_for(&second), "bb", None),
            DeferredReason::Live,
        )
        .held("second admits");
        drop(dropped);
        let stats = table.prune(0);
        assert_eq!((stats.reaped, stats.pending), (0, 1));
        assert_eq!(table.len(), 2);
        let stats = table.prune(1);
        assert_eq!((stats.reaped, stats.pending), (1, 0));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn same_open_file_proofs_merge_to_one_row() {
        let (_dir, path) = fixture_bytes("lib.so", b"shared-bytes");
        let key = maps_key_for(&path);
        let mut table = HandleTable::new(2);
        let first = acquire(
            &mut table,
            proved(&path, key, "aa", Some(mapped_proof_for(key))),
            DeferredReason::Live,
        )
        .held("first admits");
        assert!(first.inserted);
        let own = MappedFile {
            identity: FileIdentity { dev: 7, ino: 7 },
            fs_magic: Some(0xef53),
        };
        let second = acquire(
            &mut table,
            proved(&path, key, "aa", Some(own)),
            DeferredReason::Live,
        )
        .held("same maps, fstat, pin, digest and unique inodes merge");
        assert!(!second.inserted);
        assert_eq!(table.len(), 1);
        assert_eq!(
            second.mapped,
            Some(own),
            "a borrower with its own proof keeps it"
        );
    }

    #[test]
    fn copy_up_pair_files_two_rows() {
        let (_d1, lower) = fixture_bytes("lower.so", b"same-bytes");
        let (_d2, upper) = fixture_bytes("upper.so", b"same-bytes");
        // One maps key (the merged mapping), two kernel files.
        let key = maps_key_for(&lower);
        let mut table = HandleTable::new(2);
        let first = acquire(
            &mut table,
            proved(&lower, key, "aa", Some(mapped_proof_for(key))),
            DeferredReason::Live,
        )
        .held("lower admits");
        assert!(first.inserted);
        let second = acquire(
            &mut table,
            proved(&upper, key, "aa", Some(mapped_proof_for(key))),
            DeferredReason::Live,
        )
        .held("upper admits beside it");
        assert!(second.inserted, "distinct kernel files never merge");
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn unhashed_entries_never_share() {
        let (_dir, path) = fixture_bytes("lib.so", b"shared-bytes");
        let key = maps_key_for(&path);
        let mapped = mapped_proof_for(key);
        let mut table = HandleTable::new(2);
        let first = acquire(
            &mut table,
            proved(&path, key, "", Some(mapped)),
            DeferredReason::Live,
        )
        .held("first admits");
        assert!(first.inserted);
        let second = acquire(
            &mut table,
            proved(&path, key, "", Some(mapped)),
            DeferredReason::Live,
        )
        .held("second admits beside it");
        assert!(second.inserted, "empty digests never share");
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn nonunique_inode_files_never_share() {
        let (_dir, path) = fixture_bytes("lib.so", b"shared-bytes");
        let key = maps_key_for(&path);
        let mapped = mapped_proof_for(key);
        let mut table = HandleTable::new(2);
        let first = acquire(
            &mut table,
            proved(&path, key, "aa", Some(mapped)).with_unique(false),
            DeferredReason::Live,
        )
        .held("first admits");
        assert!(first.inserted);
        let second = acquire(
            &mut table,
            proved(&path, key, "aa", Some(mapped)).with_unique(false),
            DeferredReason::Live,
        )
        .held("second admits beside it");
        assert!(second.inserted, "non-unique inodes never share");
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn unmapped_acquire_files_row_without_mapped() {
        let (_dir, path) = fixture_bytes("lib.so", b"shared-bytes");
        let key = maps_key_for(&path);
        let mut table = HandleTable::new(2);
        let first = acquire(
            &mut table,
            proved(&path, key, "aa", None),
            DeferredReason::Live,
        )
        .held("unmapped admits");
        assert!(first.inserted);
        assert_eq!(first.mapped, None);
        assert_eq!(table.len(), 1);
        let second = acquire(
            &mut table,
            proved(&path, key, "aa", None),
            DeferredReason::Live,
        )
        .held("second admits beside it");
        assert!(
            second.inserted,
            "a resident without a mapped proof never lends"
        );
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn adopt_never_refuses_past_the_cap() {
        let (_d1, first) = fixture_bytes("first.so", b"first-bytes");
        let (_d2, second) = fixture_bytes("second.so", b"second-bytes");
        let mut table = HandleTable::new(1);
        let first = adopt(&mut table, proved(&first, maps_key_for(&first), "aa", None));
        assert!(first.inserted);
        let second = adopt(
            &mut table,
            proved(&second, maps_key_for(&second), "bb", None),
        );
        assert!(second.inserted, "count-only adopt files past the cap");
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn adopt_existing_dedups_by_open_file() {
        let (_d1, first) = fixture_bytes("first.so", b"first-bytes");
        let (_d2, second) = fixture_bytes("second.so", b"second-bytes");
        let mut table = HandleTable::new(2);
        let arc = std::sync::Arc::new(std::fs::File::open(&first).unwrap());
        let one = table.adopt_existing(&TableHandle::for_test(arc.clone()));
        assert!(one.inserted);
        let two = table.adopt_existing(&TableHandle::for_test(arc.clone()));
        assert!(!two.inserted, "one row per distinct open file");
        assert_eq!(one.handle.id(), two.handle.id());
        assert_eq!(table.len(), 1);
        let other = std::sync::Arc::new(std::fs::File::open(&second).unwrap());
        let three = table.adopt_existing(&TableHandle::for_test(other));
        assert!(three.inserted);
        assert_eq!(table.len(), 2);
    }
}
