//! SPDX-License-Identifier: GPL-3.0-or-later
//! DR-C1b-3 (owner ruling, C5.6): the per-range `map_files` proof stats of
//! one collection, run on a small bounded pool.
//!
//! Only the stat syscalls move off the calling thread. Every decision —
//! which ranges are statted, the work budget charged for each, the pin
//! that brackets them, and what each result means — stays on the caller,
//! in the serial order; the pool returns exactly the results the serial
//! loop would, in the same order (see [`stat_batch`]). Nothing is cached:
//! each stat is a fresh `fstatat` of the target's own `map_files` entry
//! (R-C56-1).
//!
//! Bounds: at most [`MAX_PROOF_STAT_THREADS`] threads per collection,
//! the caller included, created once per collection as scoped threads
//! (they cannot outlive it) and joined when it ends. A worker opens no
//! file: it stats relative to the directory fd the caller already holds
//! for that process, so the fd budget is unchanged. If no worker can be
//! spawned, or a worker's results do not come back whole, the caller stats
//! those ranges itself: serial is always the fallback, never a partial
//! result.

use crate::discovery::identity::FileIdentity;
use std::sync::{Arc, mpsc};

/// The most threads (the calling thread included) one collection uses for
/// proof stats: past four, the targets' `mmap_lock`s and procfs lookups
/// gain little and the observer would take more of a host it shares.
pub(crate) const MAX_PROOF_STAT_THREADS: usize = 4;

/// Batches smaller than this stay on the caller: dispatching costs more
/// than it saves. Measured (exp-pass-profile, 4,096 processes): one
/// `fstatat` is ~3.4 us while one pid's channel round-trip costs ~85 us
/// at 2 threads and more at 4, so batches under ~51 ranges lose; 128
/// keeps the pool for monster mappings with clear margin.
pub(crate) const MIN_PARALLEL_BATCH: usize = 128;

/// Each worker's stack: the stat path is shallow.
const WORKER_STACK_BYTES: usize = 256 << 10;

/// One range's proof read, as the serial path reads it.
pub(crate) type StatResult = Result<FileIdentity, String>;

/// A source of `map_files` identities for one process's ranges, shareable
/// with the pool's workers.
pub(crate) trait RangeStat: Send + Sync {
    fn stat(&self, start: u64, end: u64) -> StatResult;
}

/// How many threads a collection's proof stats may use here: the
/// observer's usable CPUs (its affinity), at most
/// [`MAX_PROOF_STAT_THREADS`].
pub(crate) fn proof_stat_threads() -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZero::get)
        .unwrap_or(1)
        .min(MAX_PROOF_STAT_THREADS)
}

type Chunk = (usize, Vec<StatResult>);

struct Job {
    source: Arc<dyn RangeStat>,
    ranges: Vec<(u64, u64)>,
    index: usize,
    reply: mpsc::Sender<Chunk>,
}

/// The workers of one collection (the caller is the extra thread).
pub(crate) struct ProofStatPool {
    workers: Vec<mpsc::Sender<Job>>,
}

impl ProofStatPool {
    /// Run `body` with a pool of `threads` threads (the caller included),
    /// or with `None` when `threads <= 1` or no worker could be spawned.
    /// The workers are scoped: they end, and are joined, with `body`.
    pub(crate) fn scoped<R>(threads: usize, body: impl FnOnce(Option<&ProofStatPool>) -> R) -> R {
        std::thread::scope(|scope| {
            let mut workers = Vec::new();
            for n in 1..threads.min(MAX_PROOF_STAT_THREADS) {
                let (jobs, receiver) = mpsc::channel::<Job>();
                let spawned = std::thread::Builder::new()
                    .name(format!("p11scope-proof-{n}"))
                    .stack_size(WORKER_STACK_BYTES)
                    .spawn_scoped(scope, move || work(receiver));
                match spawned {
                    Ok(_) => workers.push(jobs),
                    Err(_) => break,
                }
            }
            let pool = ProofStatPool { workers };
            let pool_ref = (!pool.workers.is_empty()).then_some(&pool);
            body(pool_ref)
            // `pool` drops here: its senders close, every worker's loop
            // ends, and the scope joins them.
        })
    }

    #[cfg(test)]
    pub(crate) fn workers(&self) -> usize {
        self.workers.len()
    }
}

fn work(jobs: mpsc::Receiver<Job>) {
    for job in jobs {
        let Job {
            source,
            ranges,
            index,
            reply,
        } = job;
        // A panicking stat must not take the collection down with the
        // scope: its chunk simply does not come back, and the caller stats
        // it serially.
        let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            ranges
                .iter()
                .map(|&(start, end)| source.stat(start, end))
                .collect::<Vec<_>>()
        }));
        if let Ok(out) = out {
            let _ = reply.send((index, out));
        }
    }
}

/// The proof reads of `ranges`, in order: exactly what
/// `ranges.iter().map(|r| source.stat(r))` returns, computed on the pool
/// when there is one and the batch is worth it. Contiguous chunks go to
/// the workers while the caller reads the first; a chunk that does not
/// come back whole (a dead worker) is read by the caller.
pub(crate) fn stat_batch(
    pool: Option<&ProofStatPool>,
    source: Arc<dyn RangeStat>,
    ranges: &[(u64, u64)],
) -> Vec<StatResult> {
    let serial = |part: &[(u64, u64)]| {
        part.iter()
            .map(|&(start, end)| source.stat(start, end))
            .collect::<Vec<_>>()
    };
    let Some(pool) = pool.filter(|_| ranges.len() >= MIN_PARALLEL_BATCH) else {
        return serial(ranges);
    };
    let size = ranges.len().div_ceil(pool.workers.len() + 1);
    let chunks: Vec<&[(u64, u64)]> = ranges.chunks(size).collect();
    let (reply, replies) = mpsc::channel::<Chunk>();
    for (index, chunk) in chunks.iter().enumerate().skip(1) {
        // A refused send (a gone worker) leaves the chunk to the caller.
        let _ = pool.workers[index - 1].send(Job {
            source: Arc::clone(&source),
            ranges: chunk.to_vec(),
            index,
            reply: reply.clone(),
        });
    }
    drop(reply);
    let mut results: Vec<Option<Vec<StatResult>>> = vec![None; chunks.len()];
    results[0] = Some(serial(chunks[0]));
    for (index, out) in replies {
        if index < chunks.len() && out.len() == chunks[index].len() && results[index].is_none() {
            results[index] = Some(out);
        }
    }
    chunks
        .iter()
        .zip(results)
        .flat_map(|(chunk, out)| out.unwrap_or_else(|| serial(chunk)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;

    /// A deterministic stat seam: each range's result is a function of the
    /// range (identities, ENOENT-style and EPERM-style errors), with a
    /// jittered delay so workers finish out of order. Records which
    /// threads served it.
    struct Fake {
        threads: Mutex<HashSet<std::thread::ThreadId>>,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl Fake {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                threads: Mutex::new(HashSet::new()),
                calls: std::sync::atomic::AtomicUsize::new(0),
            })
        }
    }

    impl RangeStat for Fake {
        fn stat(&self, start: u64, end: u64) -> StatResult {
            self.threads
                .lock()
                .unwrap()
                .insert(std::thread::current().id());
            self.calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            std::thread::sleep(std::time::Duration::from_micros((start * 7919) % 300));
            match start % 5 {
                0 => Err("no mapping (ENOENT)".into()),
                1 => Err("Operation not permitted (os error 1)".into()),
                _ => Ok(FileIdentity {
                    dev: end,
                    ino: start,
                }),
            }
        }
    }

    fn ranges(n: u64) -> Vec<(u64, u64)> {
        (0..n).map(|i| (1000 + i * 13, 2000 + i * 17)).collect()
    }

    fn serial(source: &Fake, ranges: &[(u64, u64)]) -> Vec<StatResult> {
        ranges.iter().map(|&(s, e)| source.stat(s, e)).collect()
    }

    /// The parallel path returns exactly the serial path's results, in
    /// order, for every pool size (1 = no workers) and batch size,
    /// including batches below the parallel threshold and ones that do
    /// not divide evenly; every range is read exactly once.
    #[test]
    fn the_pool_returns_exactly_the_serial_results_in_order() {
        for threads in 1..=MAX_PROOF_STAT_THREADS + 2 {
            ProofStatPool::scoped(threads, |pool| {
                let expected_workers = threads.min(MAX_PROOF_STAT_THREADS).saturating_sub(1);
                assert_eq!(pool.map_or(0, ProofStatPool::workers), expected_workers);
                for n in [
                    0,
                    1,
                    9,
                    30,
                    31,
                    97,
                    MIN_PARALLEL_BATCH as u64 - 1,
                    MIN_PARALLEL_BATCH as u64,
                    MIN_PARALLEL_BATCH as u64 + 1,
                    192,
                ] {
                    let input = ranges(n);
                    let fake = Fake::new();
                    let got = stat_batch(pool, fake.clone(), &input);
                    let calls = fake.calls.load(std::sync::atomic::Ordering::Relaxed);
                    assert_eq!(got, serial(&Fake::new(), &input), "threads {threads} n {n}");
                    assert_eq!(
                        calls,
                        input.len(),
                        "each range read once: threads {threads} n {n}"
                    );
                }
            });
        }
    }

    /// With workers, a batch above the threshold is really spread over
    /// more than one thread (else the pool would be decoration).
    #[test]
    fn a_large_batch_uses_the_workers() {
        ProofStatPool::scoped(MAX_PROOF_STAT_THREADS, |pool| {
            let fake = Fake::new();
            stat_batch(pool, fake.clone(), &ranges(192));
            assert!(fake.threads.lock().unwrap().len() > 1);
        });
    }

    /// A worker that panics (or whose result never returns) does not lose
    /// its chunk: the caller reads it, and the batch is still exactly the
    /// serial result.
    #[test]
    fn a_failed_worker_chunk_is_read_by_the_caller() {
        struct Flaky {
            inner: Arc<Fake>,
            caller: std::thread::ThreadId,
        }
        impl RangeStat for Flaky {
            fn stat(&self, start: u64, end: u64) -> StatResult {
                if std::thread::current().id() != self.caller {
                    panic!("a worker fails");
                }
                self.inner.stat(start, end)
            }
        }
        ProofStatPool::scoped(MAX_PROOF_STAT_THREADS, |pool| {
            let input = ranges(192);
            let flaky = Arc::new(Flaky {
                inner: Fake::new(),
                caller: std::thread::current().id(),
            });
            let got = stat_batch(pool, flaky, &input);
            assert_eq!(got, serial(&Fake::new(), &input));
        });
    }
}
