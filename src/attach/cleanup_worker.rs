//! SPDX-License-Identifier: GPL-3.0-or-later
//! Background link cleanup after publication (stop-gate Task 5).
//!
//! After the report is published, the session moves its links out of Aya
//! by ownership transfer and submits them here. The worker closes them in
//! [`DetachOrder`] on its own thread while the foreground prints progress
//! to stderr; a second signal interrupts the wait (the kernel finishes the
//! remaining closes at process exit).

use std::io::Write;
use std::os::fd::OwnedFd;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use aya::programs::links::FdLink;

use super::ProducerProgram;

/// A link value moved out of Aya by ownership transfer (`take_link` plus
/// `into_fd_links()` for singles; the existing fds for multi group links).
/// Detach is drop: closing the last fd detaches the kernel link. The
/// payloads are never inspected, only closed.
#[allow(dead_code)]
pub(crate) enum OwnedLink {
    Fd(FdLink),
    Multi(Vec<OwnedFd>),
}

/// The existing producer detach order from `detach_selected_with` as data:
/// entries, then `task_newtask`, then `p11_return`, then dynamic/export,
/// then raw exec/exit last.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct DetachOrder;

impl DetachOrder {
    /// Lower ranks close first. Mirrors `detach_selected_with` exactly.
    pub(crate) fn rank(&self, producer: &ProducerProgram) -> u8 {
        const EARLY: &[(ProducerProgram, u8)] = &[
            (ProducerProgram::UProbe("p11_entry"), 0),
            (ProducerProgram::UProbe("p11_entry_ia32"), 1),
            (ProducerProgram::UProbe("p11_entry_template"), 2),
            (ProducerProgram::UProbe("p11_entry_template_types"), 3),
            (ProducerProgram::UProbe("p11_entry_template_pair"), 4),
            (ProducerProgram::BtfTracePoint("task_newtask"), 5),
            (ProducerProgram::UProbe("p11_return"), 6),
        ];
        if let Some((_, rank)) = EARLY.iter().find(|(named, _)| named == producer) {
            return *rank;
        }
        match producer {
            ProducerProgram::RawTracePoint(_) => 8,
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

#[derive(Debug)]
pub(crate) struct CleanupReceipt {
    pub completed: bool,
    pub failures: Vec<String>,
}

type BoxCloser = Box<dyn FnMut(OwnedLink, ProducerProgram) -> Result<(), String> + Send>;
type BoxClock = Arc<dyn Fn() -> Duration + Send + Sync>;

enum Command {
    Submit(Vec<(OwnedLink, ProducerProgram)>),
    Shutdown,
}

#[derive(Default)]
struct WorkerState {
    total: usize,
    attempted: usize,
    released: usize,
    uncertain: usize,
    failures: Vec<String>,
    started_at: Option<Duration>,
    done: bool,
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
}

impl CleanupWorker {
    /// Pre-start the worker with the production closer (drop detaches).
    pub(crate) fn pre_start() -> Self {
        let epoch = std::time::Instant::now();
        Self::pre_start_with(
            Box::new(|link, _| {
                drop(link);
                Ok(())
            }),
            Arc::new(move || epoch.elapsed()),
        )
    }

    /// Test seam: injected closer and scripted clock. Production uses
    /// [`CleanupWorker::pre_start`].
    #[allow(dead_code)]
    pub(crate) fn pre_start_with(closer: BoxCloser, clock: BoxClock) -> Self {
        let state = Arc::new(Mutex::new(WorkerState::default()));
        let (tx, rx) = mpsc::channel::<Command>();
        let thread_state = Arc::clone(&state);
        let handle = std::thread::Builder::new()
            .name("p11scope-cleanup".to_string())
            .spawn(move || run_cleanup(rx, thread_state, closer))
            .ok();
        let start_error = if handle.is_none() {
            Some("cleanup worker thread failed to start".to_string())
        } else {
            None
        };
        Self {
            tx,
            state,
            clock,
            handle,
            start_error,
        }
    }

    /// Submit links for background closing, lowest [`DetachOrder`] rank
    /// first (stable within a rank). Single-submit discipline: the session
    /// submits once per detach, then drives this worker to completion.
    pub(crate) fn submit(&self, mut links: Vec<(OwnedLink, ProducerProgram)>, order: DetachOrder) {
        links.sort_by_key(|(_, producer)| order.rank(producer));
        let mut state = self.state.lock().unwrap();
        state.total += links.len();
        if state.started_at.is_none() {
            state.started_at = Some((self.clock)());
        }
        drop(state);
        let _ = self.tx.send(Command::Submit(links));
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
            .started_at
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

    /// True once every submitted link has been attempted (or no worker
    /// thread is running).
    fn is_done(&self) -> bool {
        if self.handle.is_none() {
            return true;
        }
        let state = self.state.lock().unwrap();
        state.attempted >= state.total
    }

    pub(crate) fn join(self) -> CleanupReceipt {
        let _ = self.tx.send(Command::Shutdown);
        if let Some(handle) = self.handle {
            let _ = handle.join();
        }
        let mut state = self.state.lock().unwrap();
        if let Some(error) = &self.start_error {
            state.uncertain = state
                .uncertain
                .saturating_add(state.total - state.attempted);
            state.attempted = state.total;
            state.failures.push(error.clone());
        }
        state.done = true;
        CleanupReceipt {
            completed: state.failures.is_empty(),
            failures: std::mem::take(&mut state.failures),
        }
    }
}

fn run_cleanup(rx: mpsc::Receiver<Command>, state: Arc<Mutex<WorkerState>>, mut closer: BoxCloser) {
    for command in rx {
        match command {
            Command::Submit(links) => {
                for (link, producer) in links {
                    state.lock().unwrap().attempted += 1;
                    match closer(link, producer) {
                        Ok(()) => {
                            state.lock().unwrap().released += 1;
                        }
                        Err(error) => {
                            let mut state = state.lock().unwrap();
                            state.uncertain += 1;
                            state.failures.push(error);
                        }
                    }
                }
            }
            Command::Shutdown => break,
        }
    }
    state.lock().unwrap().done = true;
}

/// The `Interrupted` payload carries the printed progress for tests;
/// production already printed it before returning.
#[allow(dead_code)]
pub(crate) enum CleanupExit {
    Completed(CleanupReceipt),
    Interrupted(CleanupProgress),
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

/// Print a progress line about once per `poll_interval` until the worker
/// joins, then a final completed/incomplete line. A second signal prints
/// the progress and "cleanup incomplete" and returns `Interrupted`; the
/// caller exits and the kernel finishes the remaining closes at exit.
pub(crate) fn drive_cleanup(
    worker: CleanupWorker,
    second_signal: impl Fn() -> bool,
    out: &mut dyn Write,
    poll_interval: Duration,
) -> CleanupExit {
    loop {
        if second_signal() {
            let progress = worker.progress();
            write_progress_line(out, &progress);
            let _ = writeln!(out, "p11scope: cleanup incomplete");
            return CleanupExit::Interrupted(progress);
        }
        if worker.is_done() {
            let progress = worker.progress();
            let receipt = worker.join();
            if receipt.completed {
                let _ = writeln!(
                    out,
                    "p11scope: cleanup completed, {}/{} links released, {} s",
                    progress.released,
                    progress.total,
                    progress.elapsed.as_secs(),
                );
            } else {
                let _ = writeln!(
                    out,
                    "p11scope: cleanup incomplete, {}/{} links released, {} uncertain, {} s",
                    progress.released,
                    progress.total,
                    progress.uncertain,
                    progress.elapsed.as_secs(),
                );
            }
            return CleanupExit::Completed(receipt);
        }
        write_progress_line(out, &worker.progress());
        std::thread::sleep(poll_interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let worker = CleanupWorker::pre_start_with(
            Box::new(move |_link, role| {
                recorder.lock().unwrap().push(role);
                if recorder.lock().unwrap().len() == 1 {
                    let gate = gate.lock().unwrap().take().unwrap();
                    let _ = gate.recv();
                }
                Ok(())
            }),
            scripted_clock(Arc::clone(&now)),
        );
        worker.submit(
            vec![
                multi(ProducerProgram::RawTracePoint("sched_process_exit")),
                multi(ProducerProgram::UProbe("p11_return")),
                multi(ProducerProgram::UProbe("p11_entry")),
            ],
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
        let worker = CleanupWorker::pre_start_with(
            Box::new(|_link, role| {
                if role == ProducerProgram::UProbe("p11_return") {
                    Err("close p11_return: bad fd".to_string())
                } else {
                    Ok(())
                }
            }),
            scripted_clock(Arc::new(Mutex::new(Duration::ZERO))),
        );
        worker.submit(
            vec![
                multi(ProducerProgram::UProbe("p11_entry")),
                multi(ProducerProgram::UProbe("p11_return")),
            ],
            DetachOrder,
        );
        for _ in 0..1000 {
            if worker.progress().attempted == 2 {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
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
    }

    #[test]
    fn second_signal_during_cleanup_reports_incomplete_and_exits() {
        let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
        let worker = CleanupWorker::pre_start_with(
            Box::new(move |_link, _| {
                let _ = gate_rx.recv();
                Ok(())
            }),
            scripted_clock(Arc::new(Mutex::new(Duration::from_secs(38)))),
        );
        worker.submit(
            vec![
                multi(ProducerProgram::UProbe("p11_entry")),
                multi(ProducerProgram::UProbe("p11_return")),
            ],
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
}
