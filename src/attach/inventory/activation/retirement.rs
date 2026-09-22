//! SPDX-License-Identifier: GPL-3.0-or-later
//! Owned blocking retirement work. Discovery stays with the main owner.

use super::{InventoryCleanupReceipt, InventoryDetachFailure, InventoryLinkIdentity};
use crate::events::DiscoveryItem;
use anyhow::{Result, anyhow};
use std::fs::File;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;
use std::time::Instant;

pub(super) struct RetirementLink<L> {
    pub(super) target: InventoryLinkIdentity,
    pub(super) handle: Option<L>,
    pub(super) quarantine: Option<String>,
}

pub(super) struct RetirementWork<L> {
    pub(super) links: Vec<RetirementLink<L>>,
    pub(super) receipt: InventoryCleanupReceipt,
    // These are the existing opened physical files, not reopened pathnames.
    // Keep them after links so every explicit/implicit close retains its pins.
    _leases: Vec<Arc<File>>,
}

impl<L> RetirementWork<L> {
    pub(super) fn new(links: Vec<RetirementLink<L>>, leases: Vec<Arc<File>>) -> Self {
        Self {
            links,
            receipt: InventoryCleanupReceipt::default(),
            _leases: leases,
        }
    }

    pub(super) fn run(&mut self, close: &mut impl FnMut(&mut L) -> Result<()>) {
        for index in (0..self.links.len()).rev() {
            self.receipt.attempted += 1;
            let link = &mut self.links[index];
            // The current handle remains in the owned job across catch_unwind.
            // A panic must not silently drop it or erase its physical identity.
            let result = match link.handle.as_mut() {
                Some(handle) => match catch_unwind(AssertUnwindSafe(|| close(handle))) {
                    Ok(result) => result,
                    Err(payload) => {
                        let message = payload
                            .downcast_ref::<&str>()
                            .copied()
                            .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                            .unwrap_or("non-string panic");
                        Err(anyhow!("Inventory detach panicked: {message}"))
                    }
                },
                None => Err(anyhow!(
                    "{}",
                    link.quarantine
                        .as_deref()
                        .unwrap_or("Inventory handle missing before retirement")
                )),
            };
            match result {
                Ok(()) => {
                    self.receipt.closed += 1;
                    // The normal FD close leaf has already emptied its handles.
                    // Other payload types likewise remain owned until this point.
                    drop(link.handle.take());
                }
                Err(error) => self.receipt.failures.push(InventoryDetachFailure {
                    target: link.target,
                    error,
                }),
            }
        }
    }

    pub(super) fn take_result(&mut self) -> (InventoryCleanupReceipt, Vec<RetirementLink<L>>) {
        (
            std::mem::take(&mut self.receipt),
            std::mem::take(&mut self.links),
        )
    }
}

impl<L> Drop for RetirementWork<L> {
    fn drop(&mut self) {
        // Last-resort resource guard, including unwind outside the per-close
        // catch. No allocation, and ordinary handles precede lifecycle roots.
        // This is reclamation; it does not manufacture successful receipts.
        for lifecycle in [false, true] {
            for link in self.links.iter_mut().rev() {
                if matches!(link.target, InventoryLinkIdentity::Lifecycle(_)) == lifecycle {
                    drop(link.handle.take());
                }
            }
        }
    }
}

type RetirementTask<L> = Box<dyn FnOnce() -> Option<RetirementWork<L>> + Send>;

pub(super) struct RetirementStartFailure<L> {
    pub(super) error: anyhow::Error,
    pub(super) work: RetirementWork<L>,
    // An empty worker may still be exiting after a failed initial transfer.
    // Retain its join handle, rather than silently abandoning the thread.
    pub(super) empty_worker: Option<JoinHandle<Option<RetirementWork<L>>>>,
}

pub(super) struct RetirementJob<L> {
    worker: Option<JoinHandle<Option<RetirementWork<L>>>>,
}

impl<L: Send + 'static> RetirementJob<L> {
    pub(super) fn start(
        work: RetirementWork<L>,
        close: impl FnMut(&mut L) -> Result<()> + Send + 'static,
    ) -> std::result::Result<Self, Box<RetirementStartFailure<L>>> {
        Self::start_with(work, close, |task| {
            std::thread::Builder::new()
                .name("inventory-retire".into())
                .spawn(task)
        })
    }

    pub(super) fn start_with(
        work: RetirementWork<L>,
        mut close: impl FnMut(&mut L) -> Result<()> + Send + 'static,
        spawn: impl FnOnce(RetirementTask<L>) -> std::io::Result<JoinHandle<Option<RetirementWork<L>>>>,
    ) -> std::result::Result<Self, Box<RetirementStartFailure<L>>> {
        let (sender, receiver) = mpsc::sync_channel::<RetirementWork<L>>(1);
        // Spawn first: thread creation failure cannot drop a closure that owns
        // live links. The single transfer slot contains resources, never events.
        let task = Box::new(move || {
            let Ok(mut work) = receiver.recv() else {
                return None;
            };
            work.run(&mut close);
            Some(work)
        });
        let worker = match spawn(task) {
            Ok(worker) => worker,
            Err(error) => {
                return Err(Box::new(RetirementStartFailure {
                    error: error.into(),
                    work,
                    empty_worker: None,
                }));
            }
        };
        if let Err(mpsc::SendError(work)) = sender.send(work) {
            return Err(Box::new(RetirementStartFailure {
                error: anyhow!("Inventory retirement worker closed its initial transfer"),
                work,
                empty_worker: Some(worker),
            }));
        }
        Ok(Self {
            worker: Some(worker),
        })
    }

    pub(super) fn poll(&mut self, deadline: Instant) -> Result<Option<RetirementWork<L>>> {
        if Instant::now() >= deadline {
            return Ok(None);
        }
        let worker = self
            .worker
            .as_ref()
            .ok_or_else(|| anyhow!("Inventory retirement result already collected"))?;
        if !worker.is_finished() {
            return Ok(None);
        }
        // Completion collection, not a hard realtime guarantee. Never join a
        // worker still executing a potentially blocking kernel close.
        match self.worker.take().unwrap().join() {
            Ok(Some(work)) => Ok(Some(work)),
            Ok(None) => Err(anyhow!(
                "Inventory retirement worker returned no owned work"
            )),
            Err(_) => Err(anyhow!(
                "Inventory retirement worker panicked outside close handling"
            )),
        }
    }
}

impl<L> Drop for RetirementJob<L> {
    fn drop(&mut self) {
        // The owning Inventory capability pumps its reader before reaching
        // this fallback. An isolated job still cannot abandon a live worker.
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

pub(super) fn abandon_and_reclaim_with<L: Send + 'static>(
    mut job: RetirementJob<L>,
    evidence: &RetirementFallbackEvidence,
    mut dequeue: impl FnMut() -> Option<DiscoveryItem>,
) -> Result<RetirementWork<L>> {
    evidence.begin_abandonment();
    loop {
        for _ in 0..256 {
            match dequeue() {
                Some(DiscoveryItem::Record(_)) => evidence.record_discard(false),
                Some(DiscoveryItem::Malformed) => evidence.record_discard(true),
                None => break,
            }
        }
        match job.poll(Instant::now() + std::time::Duration::from_secs(1)) {
            Ok(Some(work)) => return Ok(work),
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(1)),
            Err(error) => {
                evidence.worker_failure();
                return Err(error);
            }
        }
    }
}

/// Fixed evidence survives an abandoned pending capability when its caller
/// retains a clone. No lifecycle records are queued in this shared handle.
#[derive(Clone, Default)]
pub(super) struct RetirementFallbackEvidence(Arc<RetirementFallbackCounters>);

#[derive(Default)]
struct RetirementFallbackCounters {
    abandoned: AtomicBool,
    records: AtomicU64,
    malformed: AtomicU64,
    worker_failures: AtomicU64,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct RetirementFallbackSnapshot {
    pub(super) abandoned: bool,
    pub(super) records: u64,
    pub(super) malformed: u64,
    pub(super) worker_failures: u64,
}

impl RetirementFallbackEvidence {
    pub(super) fn begin_abandonment(&self) {
        self.0.abandoned.store(true, Ordering::Release);
    }

    pub(super) fn record_discard(&self, malformed: bool) {
        // The abandonment marker must be observable before any discard count.
        self.begin_abandonment();
        let counter = if malformed {
            &self.0.malformed
        } else {
            &self.0.records
        };
        let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            Some(value.saturating_add(1))
        });
    }

    pub(super) fn worker_failure(&self) {
        let _ = self
            .0
            .worker_failures
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                Some(value.saturating_add(1))
            });
    }

    pub(super) fn snapshot(&self) -> RetirementFallbackSnapshot {
        RetirementFallbackSnapshot {
            abandoned: self.0.abandoned.load(Ordering::Acquire),
            records: self.0.records.load(Ordering::Acquire),
            malformed: self.0.malformed.load(Ordering::Acquire),
            worker_failures: self.0.worker_failures.load(Ordering::Acquire),
        }
    }
}
