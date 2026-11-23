// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>

//! Versioned seal-scan inputs.
//!
//! A production seal scans staging across polls and keeps partial and
//! completed answers for its frame. Every adapter field such a scan
//! reads lives in one of the wrappers below, which allow shared reads
//! through `Deref` but no `DerefMut`: the only way to mutate the value
//! is a method that bumps its revision first. A scan stamps the
//! revisions it started under ([`super::SealInputRevision`]) and drops
//! every cursor, accumulator and cached decision when any of them
//! moved, so a stale answer cannot outlive a change to its inputs and
//! no writer can forget to invalidate.
//!
//! The open table additionally owns its replay cardinalities: every
//! insert, removal and entry mutation re-derives the touched entry's
//! contribution, so replay sizing reads exact counts in O(1) and the
//! counts cannot drift from the rows.

use std::collections::BTreeMap;
use std::ops::Deref;

use super::{JournalNativeKey, OpenEntry};

/// One seal-scan input: shared reads deref to the value; every
/// mutable access goes through [`Tracked::edit`], which bumps the
/// revision before handing out the mutable reference. There is no
/// `DerefMut`, so a write that skips the revision does not compile.
#[derive(Debug, Default, Clone)]
pub(super) struct Tracked<T> {
    value: T,
    revision: u64,
}

impl<T> Tracked<T> {
    pub(super) fn new(value: T) -> Self {
        Self { value, revision: 0 }
    }

    /// Mutable access: bumps the revision first, so every scan keyed on
    /// it restarts at its next use.
    pub(super) fn edit(&mut self) -> &mut T {
        self.revision = self.revision.wrapping_add(1);
        &mut self.value
    }

    pub(super) fn revision(&self) -> u64 {
        self.revision
    }
}

/// Test-only value equality (revisions ignored), for assertions that a
/// seal left an input unchanged.
#[cfg(test)]
impl<T: PartialEq> PartialEq for Tracked<T> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T> Deref for Tracked<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.value
    }
}

impl<'a, T> IntoIterator for &'a Tracked<T>
where
    &'a T: IntoIterator,
{
    type Item = <&'a T as IntoIterator>::Item;
    type IntoIter = <&'a T as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        (&self.value).into_iter()
    }
}

/// Exact replay cardinalities of the open table: unconverted begins,
/// staged ends awaiting conversion, and staged abandonments.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct OpenCounts {
    pub(super) begins: usize,
    pub(super) terminals: usize,
    pub(super) abandoned: usize,
}

impl OpenCounts {
    /// One entry's contribution: the same predicates replay sizing
    /// bounds its steps by.
    pub(super) fn of(entry: &OpenEntry) -> Self {
        Self {
            begins: usize::from(entry.converted_ticket.is_none()),
            terminals: usize::from(entry.end.is_some() && !entry.end_converted),
            abandoned: usize::from(entry.abandon.is_some()),
        }
    }

    fn add(&mut self, other: Self) {
        self.begins += other.begins;
        self.terminals += other.terminals;
        self.abandoned += other.abandoned;
    }

    fn sub(&mut self, other: Self) {
        // Every subtracted contribution was added when its entry entered
        // or last changed, so these never underflow.
        self.begins -= other.begins;
        self.terminals -= other.terminals;
        self.abandoned -= other.abandoned;
    }
}

/// The staged open table: entries by native key, their exact replay
/// cardinalities and a seal-input revision. Reads deref to the map;
/// every mutation is a method below that bumps the revision and keeps
/// the counts exact.
#[derive(Debug, Default)]
pub(super) struct OpenTable {
    entries: BTreeMap<JournalNativeKey, OpenEntry>,
    counts: OpenCounts,
    revision: u64,
}

impl Deref for OpenTable {
    type Target = BTreeMap<JournalNativeKey, OpenEntry>;

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

impl<'a> IntoIterator for &'a OpenTable {
    type Item = (&'a JournalNativeKey, &'a OpenEntry);
    type IntoIter = std::collections::btree_map::Iter<'a, JournalNativeKey, OpenEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

impl OpenTable {
    pub(super) fn revision(&self) -> u64 {
        self.revision
    }

    pub(super) fn counts(&self) -> OpenCounts {
        self.counts
    }

    fn bump(&mut self) {
        self.revision = self.revision.wrapping_add(1);
    }

    pub(super) fn insert(
        &mut self,
        native: JournalNativeKey,
        entry: OpenEntry,
    ) -> Option<OpenEntry> {
        self.bump();
        self.counts.add(OpenCounts::of(&entry));
        let old = self.entries.insert(native, entry);
        if let Some(old) = &old {
            self.counts.sub(OpenCounts::of(old));
        }
        old
    }

    pub(super) fn remove(&mut self, native: &JournalNativeKey) -> Option<OpenEntry> {
        let removed = self.entries.remove(native)?;
        self.bump();
        self.counts.sub(OpenCounts::of(&removed));
        Some(removed)
    }

    /// Drop every entry (a bulk free).
    pub(super) fn clear(&mut self) {
        self.bump();
        self.entries.clear();
        self.counts = OpenCounts::default();
    }

    /// Mutable access to one entry. The guard withdraws the entry's
    /// contribution now and re-adds it from the mutated entry when it
    /// drops, so the counts stay exact whatever the caller changes.
    pub(super) fn get_mut(&mut self, native: &JournalNativeKey) -> Option<OpenEntryMut<'_>> {
        let entry = self.entries.get_mut(native)?;
        self.revision = self.revision.wrapping_add(1);
        self.counts.sub(OpenCounts::of(entry));
        Some(OpenEntryMut {
            entry,
            counts: &mut self.counts,
        })
    }

    /// Test-only differential: recount every entry and compare with the
    /// maintained cardinalities. Never in a production or seal path.
    #[cfg(test)]
    pub(super) fn recount_for_test(&self) -> OpenCounts {
        let mut counts = OpenCounts::default();
        for entry in self.entries.values() {
            counts.add(OpenCounts::of(entry));
        }
        counts
    }
}

/// Mutable access to one open entry; restores its contribution to the
/// table's counts on drop.
pub(super) struct OpenEntryMut<'a> {
    entry: &'a mut OpenEntry,
    counts: &'a mut OpenCounts,
}

impl Deref for OpenEntryMut<'_> {
    type Target = OpenEntry;

    fn deref(&self) -> &OpenEntry {
        self.entry
    }
}

impl std::ops::DerefMut for OpenEntryMut<'_> {
    fn deref_mut(&mut self) -> &mut OpenEntry {
        self.entry
    }
}

impl Drop for OpenEntryMut<'_> {
    fn drop(&mut self) {
        self.counts.add(OpenCounts::of(self.entry));
    }
}
