// SPDX-License-Identifier: GPL-3.0-or-later
//! Capture-owned, display-only scheduling and charged immutable publication.
//!
//! No admission, provider, scope, or semantic code consumes this table. The
//! runtime only accepts an already-admitted identity and a qualified sample.

use super::acquisition::UncommittedSample;
use super::presentation::{
    CALLER_METADATA_TABLE_CEILING, CallerMetadata, MAX_CALLER_METADATA_RECORDS, MetadataReason,
    MetadataStatus,
};
use crate::discovery::caller_registry::CallerId;
#[path = "runtime/job.rs"]
pub(crate) mod job;

#[path = "runtime/work_lane.rs"]
pub(crate) mod work_lane;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

pub(crate) const REFRESH_NS: u64 = 1_000_000_000;
pub(crate) const STALE_NS: u64 = 10_000_000_000;
pub(crate) const START_WINDOW_NS: u64 = 100_000_000;
pub(crate) const STARTS_PER_WINDOW: u32 = 64;
pub(crate) const JOB_BUDGET: std::time::Duration = std::time::Duration::from_millis(25);
/// Conservative allocator bookkeeping per owned allocation, separate from RSS.
const ALLOCATION_PADDING: usize = 32;
/// The worker checks its actual job/result/wrapper sizes against this reserved
/// envelope. Two membership buffers and the thread stack are temporary scratch.
pub(crate) const WORKER_STORAGE_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MetadataCaller {
    pub(crate) id: CallerId,
    pub(crate) incarnation: u32,
    /// Only the admitted native identity; a later query cannot upgrade a scan.
    pub(crate) image: Option<(u64, u64)>,
    pub(crate) retired: bool,
}

/// Private job coordinates. Sequence/fence never wrap into old freshness.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct JobTicket {
    pub(crate) epoch: u64,
    pub(crate) caller: MetadataCaller,
    sequence: u64,
    fence: u64,
    pub(crate) started_ns: u64,
}

#[derive(Clone, Copy)]
struct Slot {
    caller: MetadataCaller,
    metadata: CallerMetadata,
    sequence: u64,
    last_attempt_ns: Option<u64>,
}

#[derive(Debug)]
struct MemoryBudget {
    used: AtomicUsize,
    peak: AtomicUsize,
    refusals: AtomicU64,
}

/// Owns a pre-allocation reservation. Move with the actual allocation; Clone
/// is intentionally absent. Arc<FrameRows> clones share, rather than copy, rows.
#[derive(Debug)]
pub(crate) struct MemoryCharge {
    budget: Arc<MemoryBudget>,
    bytes: usize,
}
impl MemoryCharge {
    fn reserve(budget: &Arc<MemoryBudget>, bytes: usize) -> Option<Self> {
        let previous = budget
            .used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= CALLER_METADATA_TABLE_CEILING)
            })
            .map_err(|_| {
                budget.refusals.fetch_add(1, Ordering::Relaxed);
            })
            .ok()?;
        budget.peak.fetch_max(previous + bytes, Ordering::AcqRel);
        Some(Self {
            budget: Arc::clone(budget),
            bytes,
        })
    }
}
impl Drop for MemoryCharge {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

fn arc_bytes<T>() -> usize {
    std::alloc::Layout::new::<[AtomicUsize; 2]>()
        .extend(std::alloc::Layout::new::<T>())
        .expect("fixed metadata layout")
        .0
        .pad_to_align()
        .size()
        + ALLOCATION_PADDING
}

#[derive(Clone, Copy, Debug)]
struct FrameRow {
    caller: CallerId,
    metadata: CallerMetadata,
}
#[derive(Debug)]
struct FrameRows {
    // Release data before its reservation; no metadata strings or paths.
    rows: Box<[FrameRow]>,
    _storage: MemoryCharge,
}

/// The only immutable projection: all consumers share these actual bytes.
#[derive(Clone, Debug, Default)]
pub(crate) struct MetadataFrame {
    rows: Option<Arc<FrameRows>>,
    refused_revision: Option<u64>,
    pub(crate) summary: MetadataSummary,
}
impl MetadataFrame {
    pub(crate) fn contains(&self, caller: CallerId) -> bool {
        self.rows.as_ref().is_some_and(|rows| {
            rows.rows
                .binary_search_by_key(&caller, |row| row.caller)
                .is_ok()
        })
    }

    /// Off has no table, allocations, reads, or caller metadata field.
    pub(crate) fn metadata(&self, caller: CallerId) -> Option<CallerMetadata> {
        if !self.summary.enabled {
            return None;
        }
        if let Some(revision) = self.refused_revision {
            return Some(CallerMetadata::unknown(
                MetadataReason::LookupLimit,
                revision,
            ));
        }
        Some(
            self.rows
                .as_ref()
                .and_then(|rows| {
                    rows.rows
                        .binary_search_by_key(&caller, |row| row.caller)
                        .ok()
                        .map(|index| rows.rows[index].metadata)
                })
                .unwrap_or_else(CallerMetadata::pending),
        )
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct MetadataSummary {
    pub(crate) enabled: bool,
    pub(crate) pending: usize,
    pub(crate) sampled: usize,
    pub(crate) unknown: usize,
    pub(crate) stale: usize,
    pub(crate) historical: usize,
    pub(crate) started: u64,
    pub(crate) discarded: u64,
    pub(crate) refresh_failures: u64,
    pub(crate) budget_refusals: u64,
    pub(crate) retained_bytes: usize,
    pub(crate) peak_retained_bytes: usize,
}
impl MetadataSummary {
    pub(crate) fn json(self) -> serde_json::Value {
        serde_json::json!({
            "mode": if self.enabled { "cgroup" } else { "none" },
            "pending": self.pending,
            "sampled": self.sampled,
            "unknown": self.unknown,
            "stale": self.stale,
            "historical": self.historical,
            "started": self.started.to_string(),
            "discarded": self.discarded.to_string(),
            "refresh_failures": self.refresh_failures.to_string(),
            "budget_refusals": self.budget_refusals.to_string(),
            "retained_bytes": self.retained_bytes.to_string(),
            "peak_retained_bytes": self.peak_retained_bytes.to_string(),
        })
    }
}

pub(crate) struct MetadataRuntime {
    slots: Box<[Option<Slot>]>,
    _table_storage: MemoryCharge,
    budget: Arc<MemoryBudget>,
    epoch: u64,
    fence: u64,
    cursor: usize,
    running: Option<JobTicket>,
    window_started_ns: u64,
    starts_in_window: u32,
    stopped: bool,
    summary: MetadataSummary,
}
impl MetadataRuntime {
    fn fresh_budget() -> Arc<MemoryBudget> {
        let fixed = arc_bytes::<MemoryBudget>();
        Arc::new(MemoryBudget {
            used: AtomicUsize::new(fixed),
            peak: AtomicUsize::new(fixed),
            refusals: AtomicU64::new(0),
        })
    }

    /// Shared across capture owners: an old blocked job or held frame cannot
    /// disappear from accounting when a new capture requests its own table.
    pub(crate) fn try_new(epoch: u64) -> Option<Self> {
        static BUDGET: std::sync::OnceLock<Arc<MemoryBudget>> = std::sync::OnceLock::new();
        Self::with_budget(epoch, Arc::clone(BUDGET.get_or_init(Self::fresh_budget)))
    }

    #[cfg(test)]
    fn new(epoch: u64) -> Self {
        Self::with_budget(epoch, Self::fresh_budget()).expect("one actual table fits")
    }

    fn with_budget(epoch: u64, budget: Arc<MemoryBudget>) -> Option<Self> {
        // Reservation precedes Vec's one exact-capacity allocation, including
        // this owner and its fixed table/worker-slot bookkeeping.
        let bytes = MAX_CALLER_METADATA_RECORDS * size_of::<Option<Slot>>()
            + ALLOCATION_PADDING
            + size_of::<Self>();
        let storage = MemoryCharge::reserve(&budget, bytes)?;
        let mut slots = Vec::with_capacity(MAX_CALLER_METADATA_RECORDS);
        slots.resize(MAX_CALLER_METADATA_RECORDS, None);
        assert_eq!(slots.capacity(), MAX_CALLER_METADATA_RECORDS);
        Some(Self {
            slots: slots.into_boxed_slice(),
            _table_storage: storage,
            budget,
            epoch,
            fence: 0,
            cursor: 0,
            running: None,
            window_started_ns: 0,
            starts_in_window: 0,
            stopped: epoch == 0,
            summary: MetadataSummary {
                enabled: true,
                ..MetadataSummary::default()
            },
        })
    }

    /// Reconcile only existing adapter records. Neither allocating metadata nor
    /// failing it can admit, retire, or change a caller in the real adapter.
    pub(crate) fn synchronize(
        &mut self,
        callers: impl IntoIterator<Item = MetadataCaller>,
        now: u64,
    ) {
        for caller in callers {
            let Some(slot) = self.slots.get_mut(caller.id.0 as usize) else {
                self.summary.budget_refusals = self.summary.budget_refusals.saturating_add(1);
                continue;
            };
            match slot {
                None => {
                    let metadata = if caller.retired {
                        CallerMetadata::pending().to_historical()
                    } else {
                        CallerMetadata::pending()
                    };
                    *slot = Some(Slot {
                        caller,
                        metadata,
                        sequence: 0,
                        last_attempt_ns: None,
                    });
                }
                Some(slot) if slot.caller.incarnation != caller.incarnation => {
                    // CallerId is never reused. Refuse a corrupt successor in
                    // place; it never inherits this table identity or sample.
                    slot.caller.retired = true;
                    slot.metadata = slot.metadata.to_historical();
                }
                Some(slot) => {
                    if slot.caller.retired || caller.retired {
                        slot.metadata = slot.metadata.to_historical();
                    } else if slot.caller.image != caller.image {
                        slot.metadata = CallerMetadata::unknown(
                            MetadataReason::GenerationChanged,
                            slot.metadata.revision.saturating_add(1),
                        );
                    }
                    // Retirement is monotone, even a bad later source cannot
                    // revive an old caller's pending job or historical row.
                    let retired = slot.caller.retired || caller.retired;
                    slot.caller = MetadataCaller { retired, ..caller };
                    if !retired
                        && slot
                            .metadata
                            .sample_ended_ns
                            .is_some_and(|ended| now.saturating_sub(ended) > STALE_NS)
                    {
                        slot.metadata = slot.metadata.to_stale();
                    }
                }
            }
        }
    }

    /// One round-robin candidate, at most64 starts in a fixed100ms window.
    /// Failure attempts get the same1s target interval as healthy refreshes.
    pub(crate) fn next(&mut self, now: u64) -> Option<JobTicket> {
        if self.stopped || self.running.is_some() || self.fence == u64::MAX {
            return None;
        }
        if now.saturating_sub(self.window_started_ns) >= START_WINDOW_NS {
            self.window_started_ns = now;
            self.starts_in_window = 0;
        }
        if self.starts_in_window >= STARTS_PER_WINDOW {
            return None;
        }
        for _ in 0..MAX_CALLER_METADATA_RECORDS {
            let index = self.cursor;
            self.cursor = (self.cursor + 1) % MAX_CALLER_METADATA_RECORDS;
            let Some(slot) = &mut self.slots[index] else {
                continue;
            };
            if slot.caller.retired
                || slot
                    .last_attempt_ns
                    .is_some_and(|previous| now.saturating_sub(previous) < REFRESH_NS)
            {
                continue;
            }
            slot.last_attempt_ns = Some(now);
            let Some(sequence) = slot.sequence.checked_add(1) else {
                slot.metadata = CallerMetadata::unknown(MetadataReason::LookupLimit, u64::MAX);
                continue;
            };
            slot.sequence = sequence;
            if slot.caller.image.is_none_or(|(cookie, _)| cookie == 0) {
                slot.metadata = CallerMetadata::unknown(
                    MetadataReason::IdentityUnavailable,
                    slot.metadata.revision.saturating_add(1),
                );
                self.summary.refresh_failures = self.summary.refresh_failures.saturating_add(1);
                continue;
            }
            let ticket = JobTicket {
                epoch: self.epoch,
                caller: slot.caller,
                sequence,
                fence: self.fence,
                started_ns: now,
            };
            self.running = Some(ticket);
            self.starts_in_window += 1;
            self.summary.started = self.summary.started.saturating_add(1);
            return Some(ticket);
        }
        None
    }

    /// Metadata work owns its independent reservation through completion even
    /// if the capture owner stops. Never charged to the H3 semantic pool.
    pub(crate) fn reserve_worker(&self) -> Option<MemoryCharge> {
        MemoryCharge::reserve(&self.budget, WORKER_STORAGE_BYTES)
    }

    pub(crate) fn refuse(&mut self, ticket: JobTicket, reason: MetadataReason) {
        self.finish(ticket, ticket.caller, Err(reason), ticket.started_ns);
    }

    fn ticket_current(&self, ticket: JobTicket, current: MetadataCaller) -> bool {
        self.running == Some(ticket)
            && !self.stopped
            && ticket.epoch == self.epoch
            && ticket.fence == self.fence
            && ticket.fence != u64::MAX
            && current == ticket.caller
            && !current.retired
            && self
                .slots
                .get(ticket.caller.id.0 as usize)
                .and_then(Option::as_ref)
                .is_some_and(|slot| slot.caller == current && slot.sequence == ticket.sequence)
    }

    // Only the worker qualification child can publish a real sample. A raw
    // UncommittedSample is not accepted by the coordinator/public API.
    fn finish(
        &mut self,
        ticket: JobTicket,
        current: MetadataCaller,
        result: Result<UncommittedSample, MetadataReason>,
        ended_ns: u64,
    ) -> bool {
        self.finish_with_times(ticket, current, result, ticket.started_ns, ended_ns)
    }

    fn finish_with_times(
        &mut self,
        ticket: JobTicket,
        current: MetadataCaller,
        result: Result<UncommittedSample, MetadataReason>,
        started_ns: u64,
        ended_ns: u64,
    ) -> bool {
        let owned = self.running == Some(ticket);
        if owned {
            self.running = None;
        }
        let slot = self
            .slots
            .get_mut(ticket.caller.id.0 as usize)
            .and_then(Option::as_mut);
        let accepted = owned
            && !self.stopped
            && ticket.epoch == self.epoch
            && ticket.fence == self.fence
            && ticket.fence != u64::MAX
            && current == ticket.caller
            && !current.retired
            && slot
                .as_ref()
                .is_some_and(|slot| slot.caller == current && slot.sequence == ticket.sequence);
        if !accepted {
            self.summary.discarded = self.summary.discarded.saturating_add(1);
            return false;
        }
        let slot = slot.expect("validated slot");
        let revision = slot.metadata.revision.saturating_add(1);
        slot.metadata = match result {
            Ok(sample) => CallerMetadata::sampled(revision, started_ns, ended_ns, &sample),
            Err(reason) => {
                self.summary.refresh_failures = self.summary.refresh_failures.saturating_add(1);
                CallerMetadata::unknown(reason, revision)
            }
        };
        true
    }

    /// Invalidate work started before an observed lifecycle/fence change.
    pub(crate) fn invalidate(&mut self) {
        self.fence = self.fence.saturating_add(1);
    }
    pub(crate) fn stop(&mut self) {
        self.stopped = true;
        self.invalidate();
    }

    pub(crate) fn frame(&self) -> MetadataFrame {
        self.snapshot(None)
    }
    pub(crate) fn frame_at(&self, now_ns: u64) -> MetadataFrame {
        self.snapshot(Some(now_ns))
    }
    fn snapshot(&self, now_ns: Option<u64>) -> MetadataFrame {
        let count = self.slots.iter().flatten().count();
        let bytes = count * size_of::<FrameRow>()
            + ALLOCATION_PADDING
            + arc_bytes::<FrameRows>()
            + size_of::<MetadataFrame>();
        let Some(storage) = MemoryCharge::reserve(&self.budget, bytes) else {
            let mut summary = self.census();
            summary.pending = 0;
            summary.sampled = 0;
            summary.stale = 0;
            summary.historical = 0;
            summary.unknown = count;
            return MetadataFrame {
                rows: None,
                refused_revision: Some(self.summary.started),
                summary,
            };
        };
        let mut rows = Vec::with_capacity(count);
        rows.extend(self.slots.iter().flatten().map(|slot| FrameRow {
            caller: slot.caller.id,
            metadata: if now_ns.is_some_and(|now| {
                slot.metadata
                    .sample_ended_ns
                    .is_some_and(|ended| now.saturating_sub(ended) > STALE_NS)
            }) {
                slot.metadata.to_stale()
            } else {
                slot.metadata
            },
        }));
        assert_eq!(rows.capacity(), count);
        let rows = Arc::new(FrameRows {
            rows: rows.into_boxed_slice(),
            _storage: storage,
        });
        let mut summary = self.census();
        summary.pending = 0;
        summary.sampled = 0;
        summary.unknown = 0;
        summary.stale = 0;
        summary.historical = 0;
        for row in rows.rows.iter() {
            match row.metadata.status {
                MetadataStatus::Pending => summary.pending += 1,
                MetadataStatus::Sampled => summary.sampled += 1,
                MetadataStatus::Unknown => summary.unknown += 1,
                MetadataStatus::Stale => summary.stale += 1,
                MetadataStatus::Historical => summary.historical += 1,
            }
        }
        MetadataFrame {
            rows: Some(rows),
            refused_revision: None,
            summary,
        }
    }

    fn census(&self) -> MetadataSummary {
        let mut summary = MetadataSummary {
            pending: 0,
            sampled: 0,
            unknown: 0,
            stale: 0,
            historical: 0,
            ..self.summary
        };
        for slot in self.slots.iter().flatten() {
            match slot.metadata.status {
                MetadataStatus::Pending => summary.pending += 1,
                MetadataStatus::Sampled => summary.sampled += 1,
                MetadataStatus::Unknown => summary.unknown += 1,
                MetadataStatus::Stale => summary.stale += 1,
                MetadataStatus::Historical => summary.historical += 1,
            }
        }
        summary.budget_refusals = summary
            .budget_refusals
            .saturating_add(self.budget.refusals.load(Ordering::Acquire));
        summary.retained_bytes = self.budget.used.load(Ordering::Acquire);
        summary.peak_retained_bytes = self.budget.peak.load(Ordering::Acquire);
        summary
    }
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
