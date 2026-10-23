//! SPDX-License-Identifier: GPL-3.0-or-later
//! Background link retirement and terminal cleanup (stop-gate Task 5).
//!
//! The session moves owned links out of Aya and submits tagged live batches
//! or terminal cleanup to its prestarted coordinator and three helpers. At
//! most four payloads close together within one [`DetachOrder`] rank; every
//! close returns before the next rank starts. Terminal cleanup drives/join waits and prints
//! progress; a second signal interrupts that wait (the kernel finishes the
//! remaining closes at process exit).

use std::fs::File;
use std::io::Write;
use std::os::fd::OwnedFd;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use aya::programs::links::FdLink;
use aya::programs::uprobe::UProbeLink;

use super::ProducerProgram;

/// A link value moved out of Aya by ownership transfer (`take_link` plus
/// `into_fd_links()` where supported, or the intact legacy owning probe;
/// the existing fds for multi group links).
/// Detach is drop: closing the last fd detaches the kernel link. The
/// payloads are never inspected, only closed.
#[allow(dead_code)]
pub(crate) enum OwnedLink {
    Fd(FdLink),
    Multi(Vec<OwnedFd>),
    /// Aya's owning legacy perf representation; moved intact, never reopened.
    Probe(UProbeLink),
    /// Payload closes before its counter ownership guard. The entire value
    /// travels through submission failure, quarantine and explicit abandon.
    Counter {
        link: Box<OwnedLink>,
        _keepalive: Arc<super::counter_banks::CounterKeepalive>,
    },
}

impl OwnedLink {
    pub(crate) fn retain_counter(
        self,
        keepalive: Arc<super::counter_banks::CounterKeepalive>,
    ) -> Self {
        Self::Counter {
            link: Box::new(self),
            _keepalive: keepalive,
        }
    }
}

/// The existing producer detach order from `detach_selected_with` as data:
/// entries, then `task_newtask`, then `p11_return`, then dynamic/export,
/// then raw exec/exit and the instance continuity hooks last.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct DetachOrder;

impl DetachOrder {
    /// Lower ranks close first. Mirrors `detach_selected_with` exactly.
    pub(crate) fn rank(&self, producer: &ProducerProgram) -> u8 {
        const EARLY: &[(ProducerProgram, u8)] = &[
            (ProducerProgram::UProbe("p11_entry"), 0),
            (ProducerProgram::UProbe("p11_counter_bank_entry"), 0),
            (ProducerProgram::UProbe("p11_entry_ia32"), 1),
            (ProducerProgram::UProbe("p11_entry_template"), 2),
            (ProducerProgram::UProbe("p11_entry_template_types"), 3),
            (ProducerProgram::UProbe("p11_entry_template_pair"), 4),
            (ProducerProgram::BtfTracePoint("task_newtask"), 5),
            (ProducerProgram::UProbe("p11_return"), 6),
            (ProducerProgram::UProbe("p11_counter_bank_return"), 6),
        ];
        if let Some((_, rank)) = EARLY.iter().find(|(named, _)| named == producer) {
            return *rank;
        }
        match producer {
            ProducerProgram::RawTracePoint(_) => 8,
            ProducerProgram::InstanceHook(_) => 9,
            _ => 7,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CleanupPhase {
    Idle,
    Draining,
    Done,
}

/// The plan names every field; `drive_cleanup` renders a subset per
/// line while tests pin the rest.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub(crate) struct CleanupProgress {
    pub total: usize,
    pub attempted: usize,
    pub released: usize,
    pub uncertain: usize,
    pub remaining: usize,
    pub phase: CleanupPhase,
    pub elapsed: Duration,
}

/// What settled once the worker thread is reaped. The final line is
/// derived from these counts, never from a progress snapshot: a
/// snapshot taken while a close is still in flight would skew the
/// released count. `uncertain` folds in links whose ownership
/// transfer out of Aya failed (see
/// [`CleanupWorker::note_transfer_failed`]), so a known transfer
/// failure can never print an unqualified "completed".
#[derive(Debug)]
pub(crate) struct CleanupReceipt {
    pub completed: bool,
    pub released: usize,
    pub total: usize,
    pub uncertain: usize,
    pub elapsed: Duration,
    pub failures: Vec<String>,
}

type LinkCloser =
    dyn Fn(&mut Option<OwnedLink>, ProducerProgram) -> Result<(), String> + Send + Sync;
pub(crate) type BoxCloser = Box<LinkCloser>;
type BoxClock = Arc<dyn Fn() -> Duration + Send + Sync>;

/// Legacy functional fixtures intentionally serialize their mutable leaf.
/// Production and concurrency/lifetime controls use BoxCloser directly.
#[cfg(test)]
pub(crate) fn legacy_test_closer(
    closer: Box<dyn FnMut(OwnedLink, ProducerProgram) -> Result<(), String> + Send>,
) -> BoxCloser {
    let closer = Mutex::new(closer);
    Box::new(move |payload, producer| {
        let owned = payload.take().ok_or("legacy fixture payload missing")?;
        closer.lock().unwrap_or_else(|error| error.into_inner())(owned, producer)
    })
}

pub(crate) type FileLeases = Arc<Vec<Arc<File>>>;
pub(crate) type CloseSlot<T> = Arc<Mutex<T>>;
type CloseOperation<T> = Arc<dyn Fn(&mut T) -> Result<(), String> + Send + Sync>;
type CloseTask = Box<dyn FnOnce() + Send>;

pub(crate) struct CloseResult<T> {
    pub(crate) slot: CloseSlot<T>,
    pub(crate) result: Result<(), String>,
}

/// Three empty helpers plus their owning coordinator close at most four
/// payloads. The coordinator retains every slot until actual results return.
/// A slot owns its original file leases through panic and inner destruction.
pub(crate) struct ClosePool<T> {
    senders: Vec<mpsc::SyncSender<CloseSlot<T>>>,
    results: mpsc::Receiver<CloseResult<T>>,
    helpers: Vec<std::thread::JoinHandle<()>>,
    operation: CloseOperation<T>,
    broken: Option<String>,
}

impl<T: Send + 'static> ClosePool<T> {
    pub(crate) fn start(operation: CloseOperation<T>) -> Result<Self, String> {
        Self::start_with(operation, |task| {
            std::thread::Builder::new()
                .name("p11scope-close".into())
                .spawn(task)
        })
    }

    pub(crate) fn start_with(
        operation: CloseOperation<T>,
        mut spawn: impl FnMut(CloseTask) -> std::io::Result<std::thread::JoinHandle<()>>,
    ) -> Result<Self, String> {
        let (results_tx, results) = mpsc::channel();
        let mut pool = Self {
            senders: Vec::new(),
            results,
            helpers: Vec::new(),
            operation,
            broken: None,
        };
        for _ in 0..3 {
            let (sender, receiver) = mpsc::sync_channel(1);
            let operation = Arc::clone(&pool.operation);
            let results = results_tx.clone();
            let task = Box::new(move || {
                while let Ok(slot) = receiver.recv() {
                    let result = invoke_close(&slot, &operation);
                    if results.send(CloseResult { slot, result }).is_err() {
                        break;
                    }
                }
            });
            match spawn(task) {
                Ok(helper) => {
                    pool.senders.push(sender);
                    pool.helpers.push(helper);
                }
                Err(error) => {
                    // No payload has entered any helper. Drop joins only the
                    // already-started empty helpers, leaving owner custody.
                    return Err(format!("owned closer helper failed to start: {error}"));
                }
            }
        }
        Ok(pool)
    }

    pub(crate) fn close_chunk(&mut self, slots: &[CloseSlot<T>]) -> Vec<CloseResult<T>> {
        assert!(!slots.is_empty() && slots.len() <= 4);
        if let Some(error) = &self.broken {
            return slots
                .iter()
                .map(|slot| CloseResult {
                    slot: Arc::clone(slot),
                    result: Err(error.clone()),
                })
                .collect();
        }
        let mut waiting = Vec::new();
        let mut returned = Vec::new();
        for (sender, slot) in self.senders.iter().zip(&slots[..slots.len() - 1]) {
            if sender.send(Arc::clone(slot)).is_err() {
                self.broken = Some("owned closer dispatch failed; payload remains retained".into());
                break;
            }
            waiting.push(Arc::clone(slot));
        }
        if self.broken.is_none() {
            let slot = slots.last().unwrap();
            returned.push(CloseResult {
                slot: Arc::clone(slot),
                result: invoke_close(slot, &self.operation),
            });
        }
        while !waiting.is_empty() && self.broken.is_none() {
            match self.results.recv_timeout(Duration::from_millis(50)) {
                Ok(result) => {
                    if let Some(index) = waiting
                        .iter()
                        .position(|slot| Arc::ptr_eq(slot, &result.slot))
                    {
                        waiting.swap_remove(index);
                        returned.push(result);
                    } else {
                        self.broken = Some("owned closer returned a foreign result".into());
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout)
                    if self.helpers.iter().all(|helper| !helper.is_finished()) => {}
                Err(_) => self.broken = Some("owned closer ended without a returned result".into()),
            }
        }
        if self.broken.is_some() {
            self.finish_helpers();
            // Join first: a dispatch/worker failure cannot leave an in-flight
            // destructor behind while a later detach rank starts.
            while let Ok(result) = self.results.try_recv() {
                if slots.iter().any(|slot| Arc::ptr_eq(slot, &result.slot))
                    && !returned
                        .iter()
                        .any(|prior| Arc::ptr_eq(&prior.slot, &result.slot))
                {
                    returned.push(result);
                }
            }
            for slot in slots {
                if !returned
                    .iter()
                    .any(|result| Arc::ptr_eq(slot, &result.slot))
                {
                    returned.push(CloseResult {
                        slot: Arc::clone(slot),
                        result: Err(self.broken.as_ref().unwrap().clone()),
                    });
                }
            }
        }
        returned
    }
}

impl<T> ClosePool<T> {
    fn finish_helpers(&mut self) {
        self.senders.clear();
        for helper in self.helpers.drain(..) {
            if helper.join().is_err() {
                self.broken
                    .get_or_insert_with(|| "owned closer helper panicked".into());
            }
        }
    }
}

impl<T> Drop for ClosePool<T> {
    fn drop(&mut self) {
        self.finish_helpers();
    }
}

fn invoke_close<T>(slot: &CloseSlot<T>, operation: &CloseOperation<T>) -> Result<(), String> {
    let mut item = slot
        .lock()
        .map_err(|_| "owned close slot is poisoned".to_string())?;
    match catch_unwind(AssertUnwindSafe(|| operation(&mut item))) {
        Ok(result) => result,
        Err(payload) => {
            let message = payload
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                .unwrap_or("non-string panic");
            Err(format!("owned detach panicked: {message}"))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BatchStatus {
    Pending,
    Released,
    Failed,
}

#[derive(Clone)]
pub(crate) struct BatchTicket {
    owner: Arc<Mutex<WorkerState>>,
    state: Arc<Mutex<BatchState>>,
}

struct BatchState {
    total: usize,
    released: usize,
    failed: bool,
    _leases: FileLeases,
}

impl std::fmt::Debug for BatchTicket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BatchTicket(<owned cleanup>)")
    }
}

impl BatchTicket {
    pub(crate) fn status(&self) -> BatchStatus {
        let Ok(state) = self.state.lock() else {
            return BatchStatus::Failed;
        };
        if state.failed {
            BatchStatus::Failed
        } else if state.released == state.total {
            BatchStatus::Released
        } else {
            BatchStatus::Pending
        }
    }

    pub(crate) fn belongs_to(&self, worker: &CleanupWorker) -> bool {
        Arc::ptr_eq(&self.owner, &worker.state)
    }
}

pub(crate) struct SubmissionFailure {
    pub(crate) message: String,
    pub(crate) links: Vec<(OwnedLink, ProducerProgram)>,
    // Payloads drop before this guard, including returned transfer failures.
    _leases: FileLeases,
}

impl std::fmt::Debug for SubmissionFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SubmissionFailure")
            .field("message", &self.message)
            .field("owned_links", &self.links.len())
            .finish()
    }
}

enum Command {
    Submit {
        links: Vec<(OwnedLink, ProducerProgram)>,
        batch: Arc<Mutex<BatchState>>,
        leases: FileLeases,
    },
    Shutdown,
}

#[derive(Default)]
struct WorkerState {
    total: usize,
    attempted: usize,
    released: usize,
    uncertain: usize,
    transfer_failed: usize,
    failures: Vec<String>,
    terminal_started_at: Option<Duration>,
    counts_invalid: bool,
    done: bool,
    quarantined: Vec<CloseSlot<DetailedClose>>,
}

struct DetailedClose {
    payload: Option<OwnedLink>,
    producer: ProducerProgram,
    batch: Arc<Mutex<BatchState>>,
    // Always after payload: inner Multi/Probe destructors retain actual files.
    _leases: FileLeases,
}

impl Drop for DetailedClose {
    fn drop(&mut self) {
        if let Some(payload) = self.payload.take() {
            // An uncertain slot is not a foreground close opportunity. Keep
            // its entire remaining Multi/legacy payload and original files
            // for process exit, also if the coordinator unexpectedly unwinds.
            std::mem::forget((payload, Arc::clone(&self._leases)));
        }
    }
}

impl Drop for WorkerState {
    fn drop(&mut self) {
        // Failed residual native handles cannot close on a foreground ticket
        // drop. Their complete owning slots, including files, await exit.
        std::mem::forget(std::mem::take(&mut self.quarantined));
    }
}

/// Pre-started background worker that closes submitted links in
/// [`DetachOrder`] while the foreground prints progress.
///
/// Dropping the worker never blocks: the thread is detached and keeps
/// closing in the background (at process exit the kernel finishes).
pub(crate) struct CleanupWorker {
    tx: mpsc::Sender<Command>,
    state: Arc<Mutex<WorkerState>>,
    clock: BoxClock,
    handle: Option<std::thread::JoinHandle<()>>,
    start_error: Option<String>,
    // A failed submission remains owned. Never close its potentially blocking
    // native handles on the foreground thread, including on second SIGINT.
    unsubmitted: Mutex<Vec<SubmissionFailure>>,
}

impl CleanupWorker {
    /// Pre-start the worker with the production closer (drop detaches).
    pub(crate) fn pre_start() -> Self {
        let epoch = std::time::Instant::now();
        Self::pre_start_with(
            Box::new(|link, _| {
                drop(link.take());
                Ok(())
            }),
            Arc::new(move || epoch.elapsed()),
        )
    }

    /// Test seam: injected closer and scripted clock. Production uses
    /// [`CleanupWorker::pre_start`].
    #[allow(dead_code)]
    pub(crate) fn pre_start_with(closer: BoxCloser, clock: BoxClock) -> Self {
        Self::pre_start_with_spawn(closer, clock, |task| {
            std::thread::Builder::new()
                .name("p11scope-cleanup".to_string())
                .spawn(task)
        })
    }

    pub(crate) fn pre_start_with_spawn(
        closer: BoxCloser,
        clock: BoxClock,
        spawn: impl FnOnce(Box<dyn FnOnce() + Send>) -> std::io::Result<std::thread::JoinHandle<()>>,
    ) -> Self {
        let state = Arc::new(Mutex::new(WorkerState::default()));
        let (tx, rx) = mpsc::channel::<Command>();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let thread_state = Arc::clone(&state);
        let (handle, start_error) = match spawn(Box::new(move || {
            run_cleanup(rx, thread_state, Arc::from(closer), ready_tx)
        })) {
            Ok(handle) => {
                let error = match ready_rx.recv() {
                    Ok(Ok(())) => None,
                    Ok(Err(error)) => Some(error),
                    Err(_) => Some("cleanup worker ended before closer readiness".into()),
                };
                (Some(handle), error)
            }
            Err(error) => (
                None,
                Some(format!("cleanup worker thread failed to start: {error}")),
            ),
        };
        Self {
            tx,
            state,
            clock,
            handle,
            start_error,
            unsubmitted: Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn live_admission(&self) -> Result<(), String> {
        if let Some(error) = &self.start_error {
            return Err(error.clone());
        }
        if self
            .handle
            .as_ref()
            .is_none_or(std::thread::JoinHandle::is_finished)
        {
            return Err("cleanup worker is unavailable for live retirement".into());
        }
        let state = self
            .state
            .lock()
            .map_err(|_| "cleanup worker state is poisoned")?;
        if state.counts_invalid {
            return Err("cleanup worker accounting is uncertain".into());
        }
        if state.terminal_started_at.is_some() {
            return Err("terminal cleanup has already begun".into());
        }
        Ok(())
    }

    /// Queue one tagged live batch without joining or stopping the worker.
    /// Only this batch's successful closes can settle its ticket.
    pub(crate) fn submit_live(
        &self,
        links: Vec<(OwnedLink, ProducerProgram)>,
        leases: FileLeases,
        order: DetachOrder,
    ) -> Result<BatchTicket, SubmissionFailure> {
        if let Err(message) = self.live_admission() {
            self.note_transfer_failed(links.len());
            self.note_failure(message.clone());
            return Err(SubmissionFailure {
                message,
                links,
                _leases: leases,
            });
        }
        self.submit_batch(links, leases, order)
    }

    fn submit_batch(
        &self,
        mut links: Vec<(OwnedLink, ProducerProgram)>,
        leases: FileLeases,
        order: DetachOrder,
    ) -> Result<BatchTicket, SubmissionFailure> {
        links.sort_by_key(|(_, producer)| order.rank(producer));
        let mut state = self.state.lock().unwrap();
        if let Some(total) = state.total.checked_add(links.len()) {
            state.total = total;
        } else {
            state.counts_invalid = true;
            let message = "cleanup submitted-link count overflow".to_string();
            state.failures.push(message.clone());
            return Err(SubmissionFailure {
                message,
                links,
                _leases: leases,
            });
        }
        drop(state);
        let batch = Arc::new(Mutex::new(BatchState {
            total: links.len(),
            released: 0,
            failed: false,
            _leases: Arc::clone(&leases),
        }));
        match self.tx.send(Command::Submit {
            links,
            batch: Arc::clone(&batch),
            leases,
        }) {
            Ok(()) => Ok(BatchTicket {
                owner: Arc::clone(&self.state),
                state: batch,
            }),
            Err(mpsc::SendError(Command::Submit {
                links,
                batch,
                leases,
            })) => {
                batch.lock().unwrap().failed = true;
                let message =
                    "cleanup submission failed; owned native links remain quarantined".to_string();
                let mut state = self.state.lock().unwrap();
                if let Some(uncertain) = state.uncertain.checked_add(links.len()) {
                    state.uncertain = uncertain;
                } else {
                    state.counts_invalid = true;
                }
                state.failures.push(message.clone());
                Err(SubmissionFailure {
                    message,
                    links,
                    _leases: leases,
                })
            }
            Err(mpsc::SendError(Command::Shutdown)) => unreachable!("submitted a link batch"),
        }
    }

    /// Submit links for background closing, lowest [`DetachOrder`] rank
    /// first, with up to four closes in flight within one rank. All earlier live submissions remain in
    /// the cumulative receipt, while elapsed time starts at terminal cleanup.
    pub(crate) fn submit(
        &self,
        links: Vec<(OwnedLink, ProducerProgram)>,
        leases: FileLeases,
        order: DetachOrder,
    ) {
        self.begin_terminal();
        if let Err(failure) = self.submit_batch(links, leases, order) {
            self.retain_unsubmitted(failure);
        }
    }

    pub(crate) fn begin_terminal(&self) {
        self.state
            .lock()
            .unwrap()
            .terminal_started_at
            .get_or_insert_with(|| (self.clock)());
    }

    pub(crate) fn has_submissions(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.total != 0 || state.transfer_failed != 0 || !state.failures.is_empty()
    }

    pub(crate) fn running(&self) -> bool {
        self.handle
            .as_ref()
            .is_some_and(|handle| !handle.is_finished())
    }

    /// Preserve ownership after a refused channel handoff. The failure was
    /// already accounted by submission; retaining it cannot credit a close.
    pub(crate) fn retain_unsubmitted(&self, failure: SubmissionFailure) {
        self.unsubmitted.lock().unwrap().push(failure);
    }

    pub(crate) fn note_failure(&self, message: String) {
        self.state.lock().unwrap().failures.push(message);
    }

    /// Record links that never reached the worker because the
    /// ownership transfer out of Aya failed. The join receipt folds
    /// the count into `uncertain` and reports incomplete. Kept
    /// separate from `uncertain` until join: completion counts settled
    /// worker closes only, and folding early would let a transfer
    /// failure mask an in-flight close.
    pub(crate) fn note_transfer_failed(&self, count: usize) {
        let mut state = self.state.lock().unwrap();
        if let Some(total) = state.transfer_failed.checked_add(count) {
            state.transfer_failed = total;
        } else {
            state.counts_invalid = true;
            state
                .failures
                .push("cleanup transfer-failure count overflow".into());
        }
    }

    pub(crate) fn progress(&self) -> CleanupProgress {
        let state = self.state.lock().unwrap();
        let remaining = state.total.saturating_sub(state.attempted);
        let phase = if state.done {
            CleanupPhase::Done
        } else if state.total == 0 {
            CleanupPhase::Idle
        } else {
            CleanupPhase::Draining
        };
        let elapsed = state
            .terminal_started_at
            .map(|started| (self.clock)().saturating_sub(started))
            .unwrap_or(Duration::ZERO);
        CleanupProgress {
            total: state.total,
            attempted: state.attempted,
            released: state.released,
            uncertain: state.uncertain,
            remaining,
            phase,
            elapsed,
        }
    }

    /// True once every submitted link has settled (released or
    /// uncertain), or no worker thread is running. Started-but-unsettled
    /// closes do not count: the final close may still be running when the
    /// last attempt lands, and the drive must stay signal-responsive until
    /// it settles.
    fn is_done(&self) -> bool {
        if self
            .handle
            .as_ref()
            .is_none_or(std::thread::JoinHandle::is_finished)
        {
            return true;
        }
        let state = self.state.lock().unwrap();
        state.released.saturating_add(state.uncertain) >= state.total
    }

    /// Reaps the worker thread and reports what settled. The receipt
    /// carries the final counts, so the drive renders the final line
    /// from it instead of a progress snapshot. The start-error path
    /// settles otherwise-unstarted links here.
    pub(crate) fn join(&mut self) -> CleanupReceipt {
        self.begin_terminal();
        let _ = self.tx.send(Command::Shutdown);
        let mut thread_failed = false;
        if let Some(handle) = self.handle.take() {
            thread_failed = handle.join().is_err();
        }
        let mut state = self.state.lock().unwrap();
        if let Some(error) = &self.start_error {
            state.failures.push(error.clone());
        }
        if thread_failed {
            state
                .failures
                .push("cleanup worker terminated before successful settlement".into());
        }
        let settled = state.released.checked_add(state.uncertain);
        let missing = settled.and_then(|settled| state.total.checked_sub(settled));
        if let Some(missing) = missing {
            state.uncertain += missing;
            if missing != 0 {
                state
                    .failures
                    .push("cleanup worker ended with unsettled native ownership".into());
            }
        } else {
            state.counts_invalid = true;
        }
        let uncertain = state.uncertain.checked_add(state.transfer_failed);
        state.counts_invalid |= uncertain.is_none();
        if state.counts_invalid {
            state
                .failures
                .push("cleanup link accounting is uncertain".into());
        }
        state.done = true;
        let elapsed = state
            .terminal_started_at
            .map(|started| (self.clock)().saturating_sub(started))
            .unwrap_or(Duration::ZERO);
        CleanupReceipt {
            completed: state.failures.is_empty()
                && state.transfer_failed == 0
                && !state.counts_invalid
                && state.released == state.total,
            released: state.released,
            total: state.total,
            uncertain: uncertain.unwrap_or(usize::MAX),
            elapsed,
            failures: std::mem::take(&mut state.failures),
        }
    }
}

impl Drop for CleanupWorker {
    fn drop(&mut self) {
        // The channel has refused these already-transferred handles. Its
        // receipt reports them uncertain, and no replacement can pass their
        // Session quarantine. Abandon only at worker destruction: closing here
        // could block stop/second SIGINT. The kernel closes them at process exit.
        let links = std::mem::take(
            self.unsubmitted
                .get_mut()
                .unwrap_or_else(|error| error.into_inner()),
        );
        if !links.is_empty() {
            std::mem::forget(links);
        }
    }
}

fn run_cleanup(
    rx: mpsc::Receiver<Command>,
    state: Arc<Mutex<WorkerState>>,
    closer: Arc<LinkCloser>,
    ready: mpsc::SyncSender<Result<(), String>>,
) {
    let close_state = Arc::clone(&state);
    let operation: CloseOperation<DetailedClose> = Arc::new(move |item| {
        // Started, not settled. No shared counter lock spans native close.
        let mut counts = close_state.lock().unwrap();
        if let Some(attempted) = counts.attempted.checked_add(1) {
            counts.attempted = attempted;
        } else {
            counts.counts_invalid = true;
        }
        drop(counts);
        closer(&mut item.payload, item.producer)?;
        if item.payload.is_some() {
            return Err("closer returned success with native ownership still retained".into());
        }
        Ok(())
    });
    let mut pool = ClosePool::start(operation);
    let _ = ready.send(pool.as_ref().map(|_| ()).map_err(Clone::clone));
    if let Err(error) = &pool {
        let mut counts = state.lock().unwrap();
        counts.counts_invalid = true;
        counts.failures.push(error.clone());
    }
    for command in rx {
        match command {
            Command::Submit {
                links,
                batch,
                leases,
            } => {
                let items: Vec<_> = links
                    .into_iter()
                    .map(|(payload, producer)| {
                        Arc::new(Mutex::new(DetailedClose {
                            payload: Some(payload),
                            producer,
                            batch: Arc::clone(&batch),
                            _leases: Arc::clone(&leases),
                        }))
                    })
                    .collect();
                let mut first = 0;
                while first < items.len() {
                    let rank = DetachOrder.rank(&items[first].lock().unwrap().producer);
                    let end = (first + 1..items.len())
                        .find(|index| {
                            DetachOrder.rank(&items[*index].lock().unwrap().producer) != rank
                        })
                        .unwrap_or(items.len());
                    for chunk in items[first..end].chunks(4) {
                        let results = match &mut pool {
                            Ok(pool) => pool.close_chunk(chunk),
                            Err(error) => chunk
                                .iter()
                                .map(|slot| CloseResult {
                                    slot: Arc::clone(slot),
                                    result: Err(error.clone()),
                                })
                                .collect(),
                        };
                        for result in results {
                            let item = result
                                .slot
                                .lock()
                                .unwrap_or_else(|error| error.into_inner());
                            let mut counts = state.lock().unwrap();
                            let mut batch = item.batch.lock().unwrap();
                            match result.result {
                                Ok(()) => {
                                    if let Some(released) = counts.released.checked_add(1) {
                                        counts.released = released;
                                    } else {
                                        counts.counts_invalid = true;
                                    }
                                    if let Some(released) = batch.released.checked_add(1) {
                                        batch.released = released;
                                    } else {
                                        batch.failed = true;
                                    }
                                }
                                Err(error) => {
                                    if let Some(uncertain) = counts.uncertain.checked_add(1) {
                                        counts.uncertain = uncertain;
                                    } else {
                                        counts.counts_invalid = true;
                                    }
                                    counts.failures.push(error);
                                    counts.quarantined.push(Arc::clone(&result.slot));
                                    batch.failed = true;
                                }
                            }
                        }
                    }
                    // Every close in this rank returned before the next rank.
                    first = end;
                }
            }
            Command::Shutdown => break,
        }
    }
    drop(pool);
    state.lock().unwrap().done = true;
}

/// The `Interrupted` payload carries the printed progress for tests;
/// production already printed it before returning.
#[allow(dead_code)]
pub(crate) enum CleanupExit {
    Completed(CleanupReceipt),
    Interrupted(CleanupProgress),
}

/// A link cleanup abandoned by a second SIGINT (SG-I7): the report is
/// already published and the kernel finishes the remaining closes at
/// process exit. Returned up the stop path so destructors and
/// post-cleanup reporting still run; `main` maps it to exit 130.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupInterrupted;

impl std::fmt::Display for CleanupInterrupted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "link cleanup interrupted by a second SIGINT; the kernel finishes the \
             remaining closes at exit",
        )
    }
}

impl std::error::Error for CleanupInterrupted {}

/// What a session does with a driven cleanup's exit: the completed
/// receipt's close failures, or the second-signal abandon as a typed
/// outcome for the caller to propagate.
pub(crate) fn settle_cleanup_exit(exit: CleanupExit) -> Result<Vec<String>, CleanupInterrupted> {
    match exit {
        CleanupExit::Completed(receipt) => Ok(receipt.failures),
        CleanupExit::Interrupted(_) => Err(CleanupInterrupted),
    }
}

fn write_progress_line(out: &mut dyn Write, progress: &CleanupProgress) {
    let _ = writeln!(
        out,
        "p11scope: cleanup {}/{} links released, {} s",
        progress.released,
        progress.total,
        progress.elapsed.as_secs(),
    );
}

/// First-pass poll: a fast session settles here instead of sleeping
/// the full printed cadence (10-50 ms keeps every capture's exit fast
/// without a busy spin).
const FIRST_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Expiry re-check granularity inside one printed cadence: long
/// `poll_interval` sleeps are sliced so a stuck close still observes
/// cancellation within ~10 ms instead of after a full second. Printing
/// stays about once per `poll_interval`; only the sleep is sliced.
const EXPIRY_POLL_SLICE: Duration = Duration::from_millis(10);

/// Sleep `total` in interruptible slices, returning early once the
/// worker settles or the expiry predicate fires. Completion still wins
/// at the top of the loop; this only shortens the sleep.
fn sleep_interruptibly(total: Duration, worker: &CleanupWorker, second_signal: &impl Fn() -> bool) {
    let mut remaining = total;
    while remaining > Duration::ZERO {
        let nap = remaining.min(EXPIRY_POLL_SLICE);
        std::thread::sleep(nap);
        remaining = remaining.saturating_sub(nap);
        if worker.is_done() || second_signal() {
            return;
        }
    }
}

/// Print a progress line about once per `poll_interval` until the worker
/// joins, then a final completed/incomplete line rendered from the join
/// receipt. The first pass polls without printing after a short sleep,
/// so a fast session exits in milliseconds instead of sleeping the full
/// cadence. Completion is checked before the second-signal predicate:
/// a signal that lands after the last close settles must not rewrite a
/// completed cleanup as incomplete. A second signal while closes are
/// still unsettled prints the progress and "cleanup incomplete" and
/// returns `Interrupted`; the caller exits and the kernel finishes the
/// remaining closes at exit. Sleeps are sliced so expiry is observed
/// within ~10 ms even under the 1 s production cadence.
pub(crate) fn drive_cleanup(
    mut worker: CleanupWorker,
    second_signal: impl Fn() -> bool,
    out: &mut dyn Write,
    poll_interval: Duration,
) -> CleanupExit {
    worker.begin_terminal();
    let mut first_poll = true;
    loop {
        if worker.is_done() {
            let receipt = worker.join();
            if receipt.completed {
                let _ = writeln!(
                    out,
                    "p11scope: cleanup completed, {}/{} links released, {} s",
                    receipt.released,
                    receipt.total,
                    receipt.elapsed.as_secs(),
                );
            } else {
                let _ = writeln!(
                    out,
                    "p11scope: cleanup incomplete, {}/{} links released, {} uncertain, {} s",
                    receipt.released,
                    receipt.total,
                    receipt.uncertain,
                    receipt.elapsed.as_secs(),
                );
            }
            return CleanupExit::Completed(receipt);
        }
        if second_signal() {
            let progress = worker.progress();
            write_progress_line(out, &progress);
            let _ = writeln!(out, "p11scope: cleanup incomplete");
            return CleanupExit::Interrupted(progress);
        }
        if first_poll {
            // A fast session is already settling: re-poll quickly without
            // printing rather than taxing every capture the full cadence.
            // Later passes print about once per `poll_interval`.
            first_poll = false;
            sleep_interruptibly(
                poll_interval.min(FIRST_POLL_INTERVAL),
                &worker,
                &second_signal,
            );
        } else {
            write_progress_line(out, &worker.progress());
            sleep_interruptibly(poll_interval, &worker, &second_signal);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_entry_closes_before_return() {
        let order = DetachOrder;
        assert!(
            order.rank(&ProducerProgram::UProbe("p11_counter_bank_entry"))
                < order.rank(&ProducerProgram::UProbe("p11_counter_bank_return"))
        );
        let mut synchronous = Vec::new();
        let failures = crate::attach::detach_selected_with(
            vec![
                (ProducerProgram::UProbe("p11_counter_bank_return"), "return"),
                (ProducerProgram::UProbe("p11_counter_bank_entry"), "entry"),
            ],
            |side| {
                synchronous.push(side);
                Ok(())
            },
        );
        assert!(failures.is_empty());
        assert_eq!(synchronous, ["entry", "return"]);
        assert!(
            order.rank(&ProducerProgram::UProbe("p11_counter_bank_return"))
                < order.rank(&ProducerProgram::RawTracePoint("sched_process_exit"))
        );
    }

    #[test]
    fn counter_keepalive_survives_failed_quarantined_and_abandoned_payloads() {
        use crate::attach::counter_banks::CounterKeepalive;
        use crate::semantics_edge::resources::{SEMANTIC_TRANSITION_SCRATCH, SemanticResourcePool};

        let pool = SemanticResourcePool::reference_limit(4 * 1024 * 1024);
        let held = CounterKeepalive::precharge(&pool.reserver(), 16 * 1024).unwrap();
        let weak = Arc::downgrade(&held);
        let (owned, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        peer.set_nonblocking(true).unwrap();
        let peer = Mutex::new(peer);
        let closing_guard = weak.clone();
        let observed_pool = pool.snapshot().charged_bytes;
        // The actual native FD closes before the guard's final refund. The
        // peer's EOF is independent of a possibly reused process FD number.
        let mut healthy = CleanupWorker::pre_start_with(
            Box::new(move |payload, _| {
                use std::io::Read;
                assert!(closing_guard.upgrade().is_some());
                let mut peer = peer.lock().unwrap();
                assert_eq!(
                    peer.read(&mut [0u8; 1]).unwrap_err().kind(),
                    std::io::ErrorKind::WouldBlock
                );
                drop(payload.take());
                assert!(closing_guard.upgrade().is_none());
                assert_eq!(peer.read(&mut [0u8; 1]).unwrap(), 0);
                Ok(())
            }),
            Arc::new(|| Duration::ZERO),
        );
        healthy.submit(
            vec![(
                OwnedLink::Multi(vec![owned.into()]).retain_counter(held),
                ProducerProgram::UProbe("p11_counter_bank_entry"),
            )],
            Arc::default(),
            DetachOrder,
        );
        assert!(healthy.join().completed);
        assert!(weak.upgrade().is_none());
        assert!(observed_pool > pool.snapshot().charged_bytes);
        assert_eq!(pool.snapshot().charged_bytes, SEMANTIC_TRANSITION_SCRATCH);
        let held = CounterKeepalive::precharge(&pool.reserver(), 32 * 1024).unwrap();
        let weak = Arc::downgrade(&held);
        let mut refused = CleanupWorker::pre_start();
        refused.begin_terminal();
        let link = OwnedLink::Multi(Vec::new()).retain_counter(held);
        let failure = refused
            .submit_live(
                vec![(link, ProducerProgram::UProbe("p11_counter_bank_entry"))],
                Arc::default(),
                DetachOrder,
            )
            .unwrap_err();
        assert!(weak.upgrade().is_some());
        assert_eq!(
            pool.snapshot().charged_bytes,
            SEMANTIC_TRANSITION_SCRATCH + 32 * 1024
        );
        refused.retain_unsubmitted(failure);
        let receipt = refused.join();
        assert!(!receipt.completed);
        assert!(
            weak.upgrade().is_some(),
            "failed submission payload owns its charge"
        );
        // Test teardown may reclaim a known non-native empty payload. Production
        // leaves uncertain real links and their keepalive retained for exit.
        refused.unsubmitted.lock().unwrap().clear();
        assert!(weak.upgrade().is_none());
        assert_eq!(pool.snapshot().charged_bytes, SEMANTIC_TRANSITION_SCRATCH);

        let held = CounterKeepalive::precharge(&pool.reserver(), 48 * 1024).unwrap();
        let weak = Arc::downgrade(&held);
        let mut failed = CleanupWorker::pre_start_with(
            Box::new(|_, _| Err("controlled close refusal".into())),
            Arc::new(|| Duration::ZERO),
        );
        failed.submit(
            vec![(
                OwnedLink::Multi(Vec::new()).retain_counter(held),
                ProducerProgram::UProbe("p11_counter_bank_return"),
            )],
            Arc::default(),
            DetachOrder,
        );
        assert!(!failed.join().completed);
        assert!(
            weak.upgrade().is_some(),
            "quarantine owns the counter guard"
        );
        let slot = failed.state.lock().unwrap().quarantined.pop().unwrap();
        let payload = slot.lock().unwrap().payload.take().unwrap();
        drop(failed);
        drop(slot);
        assert!(
            weak.upgrade().is_some(),
            "the abandoned payload carries its own guard"
        );
        drop(payload);
        assert!(weak.upgrade().is_none());
        assert_eq!(pool.snapshot().charged_bytes, SEMANTIC_TRANSITION_SCRATCH);
    }

    fn multi(role: ProducerProgram) -> (OwnedLink, ProducerProgram) {
        (OwnedLink::Multi(Vec::new()), role)
    }

    fn scripted_clock(now: Arc<Mutex<Duration>>) -> BoxClock {
        Arc::new(move || *now.lock().unwrap())
    }

    #[test]
    fn cleanup_worker_preserves_detach_order_and_reports_progress() {
        let closed: Arc<Mutex<Vec<ProducerProgram>>> = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&closed);
        let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
        let gate = Mutex::new(Some(gate_rx));
        let now = Arc::new(Mutex::new(Duration::ZERO));
        let mut worker = CleanupWorker::pre_start_with(
            legacy_test_closer(Box::new(move |_link, role| {
                recorder.lock().unwrap().push(role);
                if recorder.lock().unwrap().len() == 1 {
                    let gate = gate.lock().unwrap().take().unwrap();
                    let _ = gate.recv();
                }
                Ok(())
            })),
            scripted_clock(Arc::clone(&now)),
        );
        worker.submit(
            vec![
                multi(ProducerProgram::RawTracePoint("sched_process_exit")),
                multi(ProducerProgram::UProbe("p11_return")),
                multi(ProducerProgram::UProbe("p11_entry")),
            ],
            Arc::default(),
            DetachOrder,
        );
        let mut progress = worker.progress();
        for _ in 0..1000 {
            progress = worker.progress();
            if progress.attempted == 1 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(progress.total, 3);
        assert_eq!(
            progress.attempted, 1,
            "mid-way progress must show the first close in flight"
        );
        assert_eq!(progress.remaining, 2);
        assert_eq!(progress.phase, CleanupPhase::Draining);
        gate_tx.send(()).unwrap();
        let receipt = worker.join();
        assert!(receipt.completed);
        assert!(receipt.failures.is_empty());
        assert_eq!(
            *closed.lock().unwrap(),
            vec![
                ProducerProgram::UProbe("p11_entry"),
                ProducerProgram::UProbe("p11_return"),
                ProducerProgram::RawTracePoint("sched_process_exit"),
            ]
        );
    }

    #[test]
    fn cleanup_failure_is_reported_not_swallowed() {
        let mut worker = CleanupWorker::pre_start_with(
            legacy_test_closer(Box::new(|_link, role| {
                if role == ProducerProgram::UProbe("p11_return") {
                    Err("close p11_return: bad fd".to_string())
                } else {
                    Ok(())
                }
            })),
            scripted_clock(Arc::new(Mutex::new(Duration::ZERO))),
        );
        worker.submit(
            vec![
                multi(ProducerProgram::UProbe("p11_entry")),
                multi(ProducerProgram::UProbe("p11_return")),
            ],
            Arc::default(),
            DetachOrder,
        );
        // `attempted` is published before the closer runs. Wait for its
        // released/uncertain result before inspecting failure progress.
        for _ in 0..1000 {
            if worker.is_done() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            worker.is_done(),
            "both closes must settle before inspection"
        );
        let progress = worker.progress();
        assert_eq!(
            progress.uncertain, 1,
            "the failed close must stay visible in progress"
        );
        let receipt = worker.join();
        assert!(
            !receipt.completed,
            "a failed close must not report completed"
        );
        assert_eq!(receipt.failures.len(), 1);
        assert!(receipt.failures[0].contains("p11_return"));
        assert_eq!(
            (receipt.released, receipt.total, receipt.uncertain),
            (1, 2, 1),
            "the receipt must carry the final counts, got: {receipt:?}"
        );
    }

    #[test]
    fn second_signal_during_cleanup_reports_incomplete_and_exits() {
        let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
        let worker = CleanupWorker::pre_start_with(
            legacy_test_closer(Box::new(move |_link, _| {
                let _ = gate_rx.recv();
                Ok(())
            })),
            scripted_clock(Arc::new(Mutex::new(Duration::from_secs(38)))),
        );
        worker.submit(
            vec![
                multi(ProducerProgram::UProbe("p11_entry")),
                multi(ProducerProgram::UProbe("p11_return")),
            ],
            Arc::default(),
            DetachOrder,
        );
        let mut out = Vec::new();
        let exit = drive_cleanup(worker, || true, &mut out, Duration::from_millis(0));
        let _ = gate_tx.send(());
        match exit {
            CleanupExit::Interrupted(progress) => {
                assert_eq!(progress.total, 2);
            }
            CleanupExit::Completed(_) => {
                panic!("a second signal during cleanup must interrupt with an incomplete receipt")
            }
        }
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("cleanup incomplete"),
            "stderr must say cleanup incomplete, got: {text}"
        );
        assert!(
            text.contains("links released"),
            "stderr must show the progress, got: {text}"
        );
    }

    /// SG-I7/M11: the second-signal abandon is a typed outcome the stop
    /// path returns, never a `process::exit` deep inside the session that
    /// skips destructors, post-cleanup reporting and the caller's status.
    #[test]
    fn a_second_signal_abandons_cleanup_as_a_typed_outcome_not_a_process_exit() {
        let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
        let worker = CleanupWorker::pre_start_with(
            legacy_test_closer(Box::new(move |_link, _| {
                let _ = gate_rx.recv();
                Ok(())
            })),
            scripted_clock(Arc::new(Mutex::new(Duration::from_secs(3)))),
        );
        worker.submit(
            vec![multi(ProducerProgram::UProbe("p11_entry"))],
            Arc::default(),
            DetachOrder,
        );
        let mut out = Vec::new();
        let exit = drive_cleanup(worker, || true, &mut out, Duration::from_millis(0));
        let settled = settle_cleanup_exit(exit);
        let _ = gate_tx.send(());
        assert_eq!(settled, Err(CleanupInterrupted));
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("cleanup incomplete"), "{text}");
    }

    #[test]
    fn a_completed_cleanup_settles_to_its_close_failures() {
        let worker = CleanupWorker::pre_start_with(
            legacy_test_closer(Box::new(|_link, _| {
                Err("close p11_entry: bad fd".to_string())
            })),
            scripted_clock(Arc::new(Mutex::new(Duration::ZERO))),
        );
        worker.submit(
            vec![multi(ProducerProgram::UProbe("p11_entry"))],
            Arc::default(),
            DetachOrder,
        );
        let mut out = Vec::new();
        let exit = drive_cleanup(worker, || false, &mut out, Duration::from_millis(1));
        let failures = settle_cleanup_exit(exit).expect("no second signal");
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("p11_entry"), "{failures:?}");
    }

    /// M1: completion counts settled closes, not started ones. The last
    /// close is gated open: once started it is attempted-but-unsettled,
    /// and the worker must not report done until the close finishes.
    #[test]
    fn cleanup_completion_counts_settled_closes_not_started_ones() {
        let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
        let mut worker = CleanupWorker::pre_start_with(
            legacy_test_closer(Box::new(move |_link, role| {
                if role == ProducerProgram::UProbe("p11_return") {
                    let _ = gate_rx.recv();
                }
                Ok(())
            })),
            scripted_clock(Arc::new(Mutex::new(Duration::ZERO))),
        );
        worker.submit(
            vec![
                multi(ProducerProgram::UProbe("p11_entry")),
                multi(ProducerProgram::UProbe("p11_return")),
            ],
            Arc::default(),
            DetachOrder,
        );
        for _ in 0..1000 {
            if worker.progress().attempted == 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let progress = worker.progress();
        assert_eq!(progress.attempted, 2);
        assert!(
            !worker.is_done(),
            "a started-but-unsettled last close is not done: {progress:?}"
        );
        gate_tx.send(()).unwrap();
        let receipt = worker.join();
        assert!(receipt.completed);
    }

    /// M1: a completed cleanup prints N/N. The last close sleeps past the
    /// drive's poll, so a snapshot taken before settlement would catch it
    /// in flight and print N-1/N.
    #[test]
    fn completed_cleanup_prints_n_over_n() {
        let worker = CleanupWorker::pre_start_with(
            legacy_test_closer(Box::new(|_link, role| {
                if role == ProducerProgram::UProbe("p11_return") {
                    std::thread::sleep(Duration::from_millis(200));
                }
                Ok(())
            })),
            scripted_clock(Arc::new(Mutex::new(Duration::ZERO))),
        );
        worker.submit(
            vec![
                multi(ProducerProgram::UProbe("p11_entry")),
                multi(ProducerProgram::UProbe("p11_return")),
            ],
            Arc::default(),
            DetachOrder,
        );
        let mut out = Vec::new();
        let exit = drive_cleanup(worker, || false, &mut out, Duration::from_millis(1));
        match exit {
            CleanupExit::Completed(receipt) => {
                assert_eq!(
                    (receipt.released, receipt.total, receipt.uncertain),
                    (2, 2, 0),
                    "the final line renders receipt counts, got: {receipt:?}"
                );
            }
            CleanupExit::Interrupted(_) => {
                panic!("no signal: the drive must complete")
            }
        }
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("cleanup completed, 2/2 links released"),
            "completed cleanup must print N/N, got: {text}"
        );
    }

    /// M3: a failed ownership transfer qualifies the final line. The
    /// transfer-failed link never reaches the worker, but the join
    /// receipt folds it into `uncertain` and reports incomplete, so the
    /// drive prints "cleanup incomplete" instead of "cleanup completed".
    #[test]
    fn transfer_failure_qualifies_the_completed_line() {
        let worker = CleanupWorker::pre_start_with(
            legacy_test_closer(Box::new(|_link, _| Ok(()))),
            scripted_clock(Arc::new(Mutex::new(Duration::ZERO))),
        );
        worker.note_transfer_failed(1);
        worker.submit(
            vec![multi(ProducerProgram::UProbe("p11_entry"))],
            Arc::default(),
            DetachOrder,
        );
        let mut out = Vec::new();
        let exit = drive_cleanup(worker, || false, &mut out, Duration::from_millis(1));
        match exit {
            CleanupExit::Completed(receipt) => {
                assert!(
                    !receipt.completed,
                    "a known transfer failure must not report completed: {receipt:?}"
                );
                assert_eq!(
                    (receipt.released, receipt.total, receipt.uncertain),
                    (1, 1, 1),
                    "got: {receipt:?}"
                );
            }
            CleanupExit::Interrupted(_) => {
                panic!("no signal: the drive must complete")
            }
        }
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("cleanup incomplete, 1/1 links released, 1 uncertain"),
            "got: {text}"
        );
        assert!(
            !text.contains("cleanup completed"),
            "the transfer failure must qualify the line, got: {text}"
        );
    }

    /// M5: a signal that lands after the last close settles must not
    /// rewrite a completed cleanup as incomplete. The drive checks
    /// worker completion before the second-signal predicate.
    #[test]
    fn signal_after_last_close_still_reports_completed() {
        let worker = CleanupWorker::pre_start_with(
            legacy_test_closer(Box::new(|_link, _| Ok(()))),
            scripted_clock(Arc::new(Mutex::new(Duration::ZERO))),
        );
        worker.submit(
            vec![
                multi(ProducerProgram::UProbe("p11_entry")),
                multi(ProducerProgram::UProbe("p11_return")),
            ],
            Arc::default(),
            DetachOrder,
        );
        for _ in 0..1000 {
            if worker.is_done() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            worker.is_done(),
            "the closes must settle before the drive starts"
        );
        let mut out = Vec::new();
        let exit = drive_cleanup(worker, || true, &mut out, Duration::from_millis(1));
        assert!(
            matches!(exit, CleanupExit::Completed(_)),
            "a settled worker must complete despite the pending signal"
        );
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("cleanup completed, 2/2 links released"),
            "got: {text}"
        );
    }

    /// M1: a second signal during the final close interrupts instead of
    /// joining blindly on it. The last close is gated (with a 5 s
    /// backstop so the old join-blind shape fails as Completed rather
    /// than hanging the suite); the signal arms once the drive had time
    /// to reach the final close.
    #[test]
    fn second_signal_during_final_close_reports_incomplete() {
        let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
        let worker = CleanupWorker::pre_start_with(
            legacy_test_closer(Box::new(move |_link, role| {
                if role == ProducerProgram::UProbe("p11_return") {
                    let _ = gate_rx.recv_timeout(Duration::from_secs(5));
                }
                Ok(())
            })),
            scripted_clock(Arc::new(Mutex::new(Duration::ZERO))),
        );
        worker.submit(
            vec![
                multi(ProducerProgram::UProbe("p11_entry")),
                multi(ProducerProgram::UProbe("p11_return")),
            ],
            Arc::default(),
            DetachOrder,
        );
        let start = std::time::Instant::now();
        let mut out = Vec::new();
        let exit = drive_cleanup(
            worker,
            move || start.elapsed() >= Duration::from_millis(100),
            &mut out,
            Duration::from_millis(1),
        );
        let _ = gate_tx.send(());
        match exit {
            CleanupExit::Interrupted(progress) => {
                assert_eq!(progress.attempted, 2, "{progress:?}");
                assert!(
                    progress.released + progress.uncertain < progress.total,
                    "the final close must still be unsettled: {progress:?}"
                );
            }
            CleanupExit::Completed(_) => {
                panic!("a second signal during the final close must interrupt, not join through it")
            }
        }
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("cleanup incomplete"), "got: {text}");
    }

    /// M2: a fast session detaches in well under a second. The drive runs
    /// with the production 1 s printed cadence; the first close outlasts
    /// the first check but settles within the short first poll, so a
    /// drive that sleeps the full interval before re-polling takes the
    /// whole second.
    #[test]
    fn fast_session_detaches_well_under_one_second() {
        let worker = CleanupWorker::pre_start_with(
            legacy_test_closer(Box::new(|_link, role| {
                if role == ProducerProgram::UProbe("p11_entry") {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(())
            })),
            scripted_clock(Arc::new(Mutex::new(Duration::ZERO))),
        );
        worker.submit(
            vec![
                multi(ProducerProgram::UProbe("p11_entry")),
                multi(ProducerProgram::UProbe("p11_return")),
            ],
            Arc::default(),
            DetachOrder,
        );
        let mut out = Vec::new();
        let start = std::time::Instant::now();
        let exit = drive_cleanup(worker, || false, &mut out, Duration::from_secs(1));
        let elapsed = start.elapsed();
        assert!(matches!(exit, CleanupExit::Completed(_)));
        assert!(
            elapsed < Duration::from_millis(500),
            "a fast session must not sleep the full 1 s cadence, took {elapsed:?}"
        );
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("cleanup completed, 2/2 links released"),
            "got: {text}"
        );
    }

    /// M2: the printed cadence stays about once per poll interval on a
    /// slow session. Three 150 ms closes under a 100 ms cadence print
    /// about four progress lines — neither a line per fast poll nor
    /// silence. (The production cadence is 1 s; the 100 ms interval tests
    /// the same mechanism without a multi-second test.)
    #[test]
    fn slow_session_keeps_about_one_line_per_poll_interval() {
        let worker = CleanupWorker::pre_start_with(
            legacy_test_closer(Box::new(|_link, _| {
                std::thread::sleep(Duration::from_millis(150));
                Ok(())
            })),
            scripted_clock(Arc::new(Mutex::new(Duration::ZERO))),
        );
        worker.submit(
            vec![
                multi(ProducerProgram::UProbe("p11_entry")),
                multi(ProducerProgram::UProbe("p11_return")),
                multi(ProducerProgram::RawTracePoint("sched_process_exit")),
            ],
            Arc::default(),
            DetachOrder,
        );
        let mut out = Vec::new();
        let exit = drive_cleanup(worker, || false, &mut out, Duration::from_millis(100));
        assert!(matches!(exit, CleanupExit::Completed(_)));
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("cleanup completed, 3/3 links released"),
            "got: {text}"
        );
        let progress_lines = text
            .lines()
            .filter(|line| line.contains("links released") && !line.contains("cleanup completed"))
            .count();
        assert!(
            (2..=6).contains(&progress_lines),
            "about one line per 100 ms over ~450 ms, got {progress_lines} in: {text}"
        );
    }

    /// DR37 cancel budget: a stuck close under the real 1 s printed
    /// cadence must still observe a 100 ms expiry within the tick
    /// budget, not after a full second sleep. Fails pre-fix at ~1 s.
    #[test]
    fn cancel_budget_with_real_polling_interrupts_within_budget() {
        let worker = CleanupWorker::pre_start_with(
            legacy_test_closer(Box::new(|_link, _| {
                std::thread::sleep(Duration::from_secs(5));
                Ok(())
            })),
            scripted_clock(Arc::new(Mutex::new(Duration::ZERO))),
        );
        worker.submit(
            vec![
                multi(ProducerProgram::UProbe("p11_entry")),
                multi(ProducerProgram::UProbe("p11_return")),
            ],
            Arc::default(),
            DetachOrder,
        );
        let start = std::time::Instant::now();
        let mut out = Vec::new();
        let exit = drive_cleanup(
            worker,
            move || start.elapsed() >= Duration::from_millis(100),
            &mut out,
            Duration::from_secs(1),
        );
        let elapsed = start.elapsed();
        match exit {
            CleanupExit::Interrupted(progress) => {
                assert_eq!(progress.total, 2, "{progress:?}");
                assert!(
                    progress.released + progress.uncertain < progress.total,
                    "the stuck close must still be unsettled: {progress:?}"
                );
            }
            CleanupExit::Completed(_) => {
                panic!("a stuck close past the cancel budget must interrupt, not complete");
            }
        }
        assert!(
            elapsed < Duration::from_millis(500),
            "cancel must return within its tick budget under the real 1 s cadence, took {elapsed:?}"
        );
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("cleanup incomplete"), "got: {text}");
    }

    /// A writer that sleeps on every write, simulating sluggish
    /// stderr without blocking forever (the truly-blocked positive
    /// stays unqualified; the cancel path bypasses stderr entirely).
    struct SlowWriter {
        inner: Vec<u8>,
        delay: Duration,
    }

    impl Write for SlowWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            std::thread::sleep(self.delay);
            self.inner.write(buf)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    /// DR37 cancel budget with sluggish diagnostics: slow stderr
    /// writes plus a stuck close under the real 1 s cadence must
    /// still interrupt within the tick budget. Fails pre-fix at ~1 s.
    #[test]
    fn cancel_budget_with_slow_stderr_still_interrupts_within_budget() {
        let worker = CleanupWorker::pre_start_with(
            legacy_test_closer(Box::new(|_link, _| {
                std::thread::sleep(Duration::from_secs(5));
                Ok(())
            })),
            scripted_clock(Arc::new(Mutex::new(Duration::ZERO))),
        );
        worker.submit(
            vec![
                multi(ProducerProgram::UProbe("p11_entry")),
                multi(ProducerProgram::UProbe("p11_return")),
            ],
            Arc::default(),
            DetachOrder,
        );
        let start = std::time::Instant::now();
        let mut out = SlowWriter {
            inner: Vec::new(),
            delay: Duration::from_millis(10),
        };
        let exit = drive_cleanup(
            worker,
            move || start.elapsed() >= Duration::from_millis(100),
            &mut out,
            Duration::from_secs(1),
        );
        let elapsed = start.elapsed();
        assert!(
            matches!(exit, CleanupExit::Interrupted(_)),
            "a stuck close past the cancel budget must interrupt despite slow diagnostics"
        );
        assert!(
            elapsed < Duration::from_millis(500),
            "cancel must stay bounded with slow stderr under the real cadence, took {elapsed:?}"
        );
        let text = String::from_utf8(out.inner).unwrap();
        assert!(text.contains("cleanup incomplete"), "got: {text}");
    }
}

#[cfg(test)]
#[path = "cleanup_worker_live_tests.rs"]
mod live_tests;

#[cfg(test)]
#[path = "cleanup_worker_concurrency_tests.rs"]
pub(crate) mod concurrency_tests;
