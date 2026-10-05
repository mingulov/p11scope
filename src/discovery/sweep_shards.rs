//! SPDX-License-Identifier: GPL-3.0-or-later
//! C7 A4: the phase-1 maps sweep, sharded by contiguous pid ranges across
//! the observer's CPUs.
//!
//! Each shard is one scoped thread that opens and reads its own contiguous
//! slice of the pid list, against a private [`MapsShadowBudget`] taken from
//! the capture budget before any shard starts. A shard never touches the
//! capture budget. When every shard is done, the calling thread *replays*
//! each read, in pid order, through the very function the serial sweep
//! uses ([`read_maps_checked`]) against the capture budget, serving the
//! bytes, read results and clock readings the shard recorded. So every
//! charge (I/O bytes), every ceiling (per-snapshot bytes and entries,
//! capture I/O, deadline, clock) and the once-only stop report land on the
//! capture budget exactly where the serial sweep would put them, given the
//! same bytes and the same clock readings for each pid.
//!
//! Why the shadow reads enough: its I/O allowance starts at what the
//! capture budget had left before the sweep and only shrinks by the
//! shard's own reads, so at every pid it is at least what the capture
//! budget will have left there after the earlier shards' replays. A replay
//! therefore never asks for a byte the shard did not read (it may ask for
//! fewer, and a recorded read is then served in parts, as a short read).
//! The deadline and any sticky stop are the capture budget's own, copied,
//! so a shard stops reading where the serial sweep would at the latest.
//!
//! Nothing crosses passes: a sweep's transcripts live until its replay
//! ends (R-C56-1). Shards hold no identity: they only read maps text.

use crate::discovery::scan::{
    CaptureWorkBudget, MapsReadBudget, MapsReadBuffers, MapsReadLimits, MapsShadowBudget,
    read_maps_checked,
};
use p11scope_manifest::maps::{MapEntry, parse_maps};
use std::io::Read;
use std::ops::Range;

/// The most threads (the calling thread included) one sharded stage uses:
/// past four, procfs and the targets' `mmap_lock`s gain little and the
/// observer would take more of a host it shares.
pub(crate) const MAX_SHARD_THREADS: usize = 4;

/// The fewest pids a shard gets. One shard is one thread and one
/// contiguous range, so its fixed cost (a spawn, a join, and a replay of
/// a few microseconds per pid) is paid once per range, never per pid: the
/// C5.6 pool lost because it paid an ~85 us channel trip per ~114 us
/// batch. At ~70 us of maps work per pid, 256 pids are ~18 ms of work per
/// shard against well under 1 ms of fixed cost; at 4,096 pids on 2 to 4
/// CPUs a shard is 1,024 to 2,048 pids.
pub(crate) const MIN_PIDS_PER_SHARD: usize = 256;

/// Each shard's stack: the read and parse path is shallow.
const SHARD_STACK_BYTES: usize = 256 << 10;

/// The shard knob's environment variable.
pub(crate) const SHARD_THREADS_VAR: &str = "P11SCOPE_SHARD_THREADS";

/// How many threads a sharded stage may use here: the observer's usable
/// CPUs (`available_parallelism`: its `sched_getaffinity` mask, further
/// limited by a cgroup CPU quota), at most [`MAX_SHARD_THREADS`].
///
/// Diagnostic override: `P11SCOPE_SHARD_THREADS` pins the count (`0`/`1`
/// force the exact serial path, `N` caps at [`MAX_SHARD_THREADS`]); unset
/// or unparsable keeps the default. Read once per process; when set, one
/// stderr note reports the value used or that it was ignored.
pub(crate) fn shard_threads() -> usize {
    static KNOB: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    let default = default_threads(MAX_SHARD_THREADS);
    let knob = *KNOB.get_or_init(|| {
        let raw = std::env::var_os(SHARD_THREADS_VAR);
        let (threads, note) = resolve_thread_knob(
            SHARD_THREADS_VAR,
            "shard",
            MAX_SHARD_THREADS,
            raw.as_deref(),
            default,
        );
        if let Some(note) = note {
            eprintln!("{note}");
        }
        threads
    });
    knob.unwrap_or(default)
}

/// The observer's usable CPUs, at most `max`.
pub(crate) fn default_threads(max: usize) -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZero::get)
        .unwrap_or(1)
        .min(max)
}

/// A thread-count knob's resolution and its stderr note, without the
/// environment read: `(Some(threads), note)` when set and valid,
/// `(None, note)` when set but invalid (the caller keeps `default`),
/// `(None, None)` when unset. A value that is not UTF-8 is set, so it is
/// reported invalid; the echoed value has its control characters escaped.
pub(crate) fn resolve_thread_knob(
    var: &str,
    label: &str,
    max: usize,
    raw: Option<&std::ffi::OsStr>,
    default: usize,
) -> (Option<usize>, Option<String>) {
    let Some(raw) = raw else {
        return (None, None);
    };
    let noun = |count: usize| if count == 1 { "thread" } else { "threads" };
    let lossy = raw.to_string_lossy();
    let shown = crate::render::escape_controls(&lossy);
    match raw
        .to_str()
        .and_then(|text| parse_thread_knob(Some(text), max))
    {
        Some(threads) => (
            Some(threads),
            Some(format!(
                "p11scope: {var}={shown} selects {threads} {label} {}",
                noun(threads)
            )),
        ),
        None => (
            None,
            Some(format!(
                "p11scope: ignoring invalid {var}={shown}; using the default {default} {label} {}",
                noun(default)
            )),
        ),
    }
}

/// Parse a thread-count knob: `Some(threads)` when set and valid (`0`/`1`
/// mean serial, `N` caps at `max`), `None` when unset or unparsable.
pub(crate) fn parse_thread_knob(env: Option<&str>, max: usize) -> Option<usize> {
    match env.map(str::trim).map(str::parse::<usize>) {
        Some(Ok(0 | 1)) => Some(1),
        Some(Ok(n)) => Some(n.min(max)),
        _ => None,
    }
}

/// How many shards `pids` pids get with `threads` threads: at most
/// `threads` (capped at [`MAX_SHARD_THREADS`]), and no shard under
/// [`MIN_PIDS_PER_SHARD`] pids. `1` means the serial path.
pub(crate) fn shard_count(pids: usize, threads: usize) -> usize {
    threads
        .min(MAX_SHARD_THREADS)
        .min(pids / MIN_PIDS_PER_SHARD)
        .max(1)
}

/// `len` items split into `shards` contiguous, in-order ranges whose sizes
/// differ by at most one; together they cover `0..len` exactly once.
pub(crate) fn shard_ranges(len: usize, shards: usize) -> Vec<Range<usize>> {
    let shards = shards.clamp(1, len.max(1));
    let base = len / shards;
    let extra = len % shards;
    let mut start = 0;
    (0..shards)
        .map(|index| {
            let size = base + usize::from(index < extra);
            let range = start..start + size;
            start += size;
            range
        })
        .collect()
}

/// The phase-1 maps sweep over `pids`, in `shards` contiguous pid ranges.
/// `record` receives one result per pid, in `pids` order, exactly as the
/// serial sweep [`sweep_maps_serial`] would produce it from the same bytes
/// and clock readings; `budget` ends in the same state. `shards <= 1` is
/// the serial sweep itself.
pub(crate) fn sweep_maps<R, O, C>(
    pids: &[u32],
    budget: &mut CaptureWorkBudget,
    shards: usize,
    limits: MapsReadLimits,
    open: &O,
    now: &C,
    record: &mut dyn FnMut(u32, Result<Vec<MapEntry>, String>),
) where
    R: Read,
    O: Fn(u32) -> std::io::Result<R> + Sync,
    C: Fn() -> Option<u64> + Sync,
{
    let ranges = shard_ranges(pids.len(), shards);
    if ranges.len() <= 1 {
        sweep_maps_serial(pids, budget, limits, open, now, record);
        return;
    }
    let shadow = budget.maps_shadow();
    let reads = read_shards(pids, &ranges, shadow, limits, open, now);
    replay(reads, budget, limits, now, record);
}

/// The serial phase-1 sweep: open, read and parse each pid in order
/// against the capture budget.
pub(crate) fn sweep_maps_serial<R, O, C>(
    pids: &[u32],
    budget: &mut CaptureWorkBudget,
    limits: MapsReadLimits,
    open: &O,
    now: &C,
    record: &mut dyn FnMut(u32, Result<Vec<MapEntry>, String>),
) where
    R: Read,
    O: Fn(u32) -> std::io::Result<R>,
    C: Fn() -> Option<u64>,
{
    let mut bufs = MapsReadBuffers::default();
    for &pid in pids {
        let result = open(pid)
            .map_err(|error| error.to_string())
            .and_then(|maps| {
                read_maps_checked(maps, budget, limits, now, &mut bufs)
                    .and_then(|()| parse_maps(bufs.bytes()))
            });
        record(pid, result);
    }
}

/// Every shard's reads, in shard (so pid) order (see [`run_shards`]).
fn read_shards<R, O, C>(
    pids: &[u32],
    ranges: &[Range<usize>],
    shadow: MapsShadowBudget,
    limits: MapsReadLimits,
    open: &O,
    now: &C,
) -> Vec<Vec<ShardRead>>
where
    R: Read,
    O: Fn(u32) -> std::io::Result<R> + Sync,
    C: Fn() -> Option<u64> + Sync,
{
    run_shards(ranges, &|range: &Range<usize>| {
        read_shard(&pids[range.clone()], shadow, limits, open, now)
    })
}

/// `work` over every range, one scoped thread per range after the first,
/// which runs on the calling thread; results in range order. A range whose
/// thread cannot be spawned, or panics, is worked again on the calling
/// thread, so no range is ever lost. `work` must therefore be repeatable:
/// a shard's work only reads and records, against its own shadow budget,
/// and decides nothing (the caller's replay does).
pub(crate) fn run_shards<T, W>(ranges: &[Range<usize>], work: &W) -> Vec<T>
where
    T: Send,
    W: Fn(&Range<usize>) -> T + Sync,
{
    std::thread::scope(|scope| {
        let handles: Vec<_> = ranges
            .iter()
            .enumerate()
            .skip(1)
            .map(|(index, range)| {
                std::thread::Builder::new()
                    .name(format!("p11scope-shard-{index}"))
                    .stack_size(SHARD_STACK_BYTES)
                    .spawn_scoped(scope, move || work(range))
                    .ok()
            })
            .collect();
        let mut out = Vec::with_capacity(ranges.len());
        if let Some(first) = ranges.first() {
            out.push(work(first));
        }
        for (handle, range) in handles.into_iter().zip(ranges.iter().skip(1)) {
            let done = handle.and_then(|handle| handle.join().ok());
            out.push(done.unwrap_or_else(|| work(range)));
        }
        out
    })
}

/// One pid's phase-1 read, as a shard saw it.
struct ShardRead {
    pid: u32,
    outcome: ShardOutcome,
}

enum ShardOutcome {
    /// `/proc/<pid>/maps` did not open: the serial sweep records this
    /// without asking the budget anything.
    OpenFailed(String),
    Read(Transcript),
}

/// Everything one read took from the outside world, in order: the clock
/// readings it asked for and the result of each `read` call.
pub(crate) struct Transcript {
    samples: Vec<Option<u64>>,
    reads: Vec<Recorded>,
    /// The bytes read, kept only when the read did not end cleanly (see
    /// [`Transcript::clean`]): only then can a replay depend on them.
    bytes: Vec<u8>,
    /// `Some` exactly when the read reached end of file under no ceiling,
    /// with the parse of what it read. A replay of a clean read depends on
    /// the lengths alone (no ceiling looks at the content of a prefix of a
    /// clean snapshot), so its bytes are not kept, and a replay that also
    /// reaches end of file takes this parse.
    clean: Option<Result<Vec<MapEntry>, String>>,
}

enum Recorded {
    Data(usize),
    Eof,
    Failed(std::io::Error),
}

fn read_shard<R, O, C>(
    pids: &[u32],
    mut shadow: MapsShadowBudget,
    limits: MapsReadLimits,
    open: &O,
    now: &C,
) -> Vec<ShardRead>
where
    R: Read,
    O: Fn(u32) -> std::io::Result<R>,
    C: Fn() -> Option<u64>,
{
    let mut bufs = MapsReadBuffers::default();
    pids.iter()
        .map(|&pid| {
            let outcome = match open(pid) {
                Err(error) => ShardOutcome::OpenFailed(error.to_string()),
                Ok(maps) => {
                    ShardOutcome::Read(record_read(maps, &mut shadow, limits, now, &mut bufs).0)
                }
            };
            ShardRead { pid, outcome }
        })
        .collect()
}

/// One maps read through [`read_maps_checked`] against `budget` (a
/// shard's shadow), recorded for a replay. The second value is what the
/// read gave there when it did not end cleanly (`None`: it did, and
/// [`Transcript::clean_result`] holds the parse), so a shard can go on
/// exactly as the serial code would.
pub(crate) fn record_read<R, C, B>(
    maps: R,
    budget: &mut B,
    limits: MapsReadLimits,
    now: &C,
    bufs: &mut MapsReadBuffers,
) -> (Transcript, Option<Result<Vec<MapEntry>, String>>)
where
    R: Read,
    C: Fn() -> Option<u64> + ?Sized,
    B: MapsReadBudget + ?Sized,
{
    let mut samples = Vec::new();
    let mut reader = RecordingReader {
        inner: maps,
        reads: Vec::new(),
        bytes: Vec::new(),
    };
    let checked = read_maps_checked(
        &mut reader,
        budget,
        limits,
        || {
            let sample = now();
            samples.push(sample);
            sample
        },
        bufs,
    );
    let reached_eof = matches!(reader.reads.last(), Some(Recorded::Eof));
    let clean = checked.is_ok() && reached_eof;
    let here = checked.and_then(|()| parse_maps(bufs.bytes()));
    let (clean, unclean, bytes) = if clean {
        (Some(here), None, Vec::new())
    } else {
        (None, Some(here), reader.bytes)
    };
    (
        Transcript {
            samples,
            reads: reader.reads,
            bytes,
            clean,
        },
        unclean,
    )
}

impl Transcript {
    /// The parse of a read that ended cleanly.
    pub(crate) fn clean_result(&self) -> Option<&Result<Vec<MapEntry>, String>> {
        self.clean.as_ref()
    }
}

struct RecordingReader<R> {
    inner: R,
    reads: Vec<Recorded>,
    bytes: Vec<u8>,
}

impl<R: Read> Read for RecordingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.inner.read(buf) {
            Ok(0) => {
                self.reads.push(Recorded::Eof);
                Ok(0)
            }
            Ok(read) => {
                self.reads.push(Recorded::Data(read));
                self.bytes.extend_from_slice(&buf[..read]);
                Ok(read)
            }
            Err(error) => {
                let replayed = clone_io_error(&error);
                self.reads.push(Recorded::Failed(error));
                Err(replayed)
            }
        }
    }
}

/// An `io::Error` that renders and classifies like `error`.
fn clone_io_error(error: &std::io::Error) -> std::io::Error {
    match error.raw_os_error() {
        Some(code) => std::io::Error::from_raw_os_error(code),
        None => std::io::Error::new(error.kind(), error.to_string()),
    }
}

/// Every shard's reads, replayed in pid order against the capture budget.
fn replay<C: Fn() -> Option<u64> + ?Sized>(
    shards: Vec<Vec<ShardRead>>,
    budget: &mut CaptureWorkBudget,
    limits: MapsReadLimits,
    now: &C,
    record: &mut dyn FnMut(u32, Result<Vec<MapEntry>, String>),
) {
    let mut bufs = MapsReadBuffers::default();
    for read in shards.into_iter().flatten() {
        let result = match read.outcome {
            ShardOutcome::OpenFailed(error) => Err(error),
            ShardOutcome::Read(transcript) => {
                replay_one(transcript, budget, limits, now, &mut bufs)
            }
        };
        record(read.pid, result);
    }
}

/// One recorded read, run again through [`read_maps_checked`] against
/// `budget`: the same calls the serial sweep makes, fed from the
/// transcript instead of procfs and the clock.
pub(crate) fn replay_one<C: Fn() -> Option<u64> + ?Sized>(
    transcript: Transcript,
    budget: &mut dyn MapsReadBudget,
    limits: MapsReadLimits,
    now: &C,
    bufs: &mut MapsReadBuffers,
) -> Result<Vec<MapEntry>, String> {
    let Transcript {
        samples,
        reads,
        bytes,
        clean,
    } = transcript;
    let mut reader = ReplayReader {
        reads: reads.into_iter(),
        current: None,
        bytes,
        offset: 0,
        zero_fill: clean.is_some(),
        reached_eof: false,
    };
    let mut samples = samples.into_iter();
    let mut last = None;
    read_maps_checked(
        &mut reader,
        budget,
        limits,
        || match samples.next() {
            Some(sample) => {
                last = Some(sample);
                sample
            }
            // A replay can ask the clock once more than the shard's read
            // did: when its smaller I/O allowance splits the shard's last
            // read, which crossed a snapshot ceiling, the replay polls
            // again before it stops on the spent allowance. Repeating the
            // latest reading is a valid reading of a monotonic clock
            // there, and that poll can only stop the read.
            None => last.unwrap_or_else(now),
        },
        bufs,
    )?;
    match clean {
        Some(parsed) if reader.reached_eof => parsed,
        // A read that did not end cleanly kept its bytes: parse what the
        // replay accepted, as the serial sweep would.
        None => parse_maps(bufs.bytes()),
        // Unreachable: a clean transcript's replay is accepted only after
        // it reaches end of file. Refuse rather than parse zero fill.
        Some(_) => {
            debug_assert!(false, "a clean maps replay was accepted short of EOF");
            Err("sharded maps replay diverged from its read".into())
        }
    }
}

struct ReplayReader {
    reads: std::vec::IntoIter<Recorded>,
    /// The unserved rest of the current recorded data read.
    current: Option<usize>,
    bytes: Vec<u8>,
    offset: usize,
    zero_fill: bool,
    reached_eof: bool,
}

impl Read for ReplayReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = match self.current.take() {
            Some(left) => left,
            None => match self.reads.next() {
                Some(Recorded::Data(read)) => read,
                Some(Recorded::Eof) => {
                    self.reached_eof = true;
                    return Ok(0);
                }
                Some(Recorded::Failed(error)) => return Err(error),
                None => {
                    // Unreachable: the shadow read at least as far as any
                    // replay can go (see the module comment).
                    debug_assert!(false, "a maps replay outran its shard's read");
                    return Err(std::io::Error::other("sharded maps replay outran its read"));
                }
            },
        };
        let served = left.min(buf.len());
        if self.zero_fill {
            buf[..served].fill(0);
        } else {
            buf[..served].copy_from_slice(&self.bytes[self.offset..self.offset + served]);
        }
        self.offset += served;
        if served < left {
            self.current = Some(left - served);
        }
        Ok(served)
    }
}

#[cfg(test)]
#[path = "sweep_shards_tests.rs"]
mod tests;
