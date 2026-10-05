//! SPDX-License-Identifier: GPL-3.0-or-later
//! C7 A4: the sharded maps sweep is the serial sweep, result for result and
//! charge for charge, at every ceiling.

use super::*;
use crate::discovery::scan::{
    IO_CEILING_REASON, InventoryDiscoveryLimits, InventoryRetainedLimits, InventoryWindowLimits,
    MAPS_CEILING_REASON, MAPS_ENTRY_CEILING_REASON, MapsSweepBudgetState, SCAN_CLOCK_REASON,
    SCAN_DEADLINE_REASON, ScanLimits, WindowId,
};
use std::cell::Cell;
use std::collections::{BTreeMap, HashSet};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

const T0: u64 = 1_000_000;

thread_local! {
    /// The pid this thread opened last: the fake clock reads it, so every
    /// clock reading during one pid's read is a function of that pid, on
    /// any thread, in any interleaving.
    static CURRENT: Cell<u32> = const { Cell::new(0) };
}

/// The fake clock: `T0 + 10 * pid`, or no clock for pids in `broken`.
fn clock(broken: &HashSet<u32>) -> impl Fn() -> Option<u64> + Sync + '_ {
    move || {
        let pid = CURRENT.with(Cell::get);
        (!broken.contains(&pid)).then(|| T0 + 10 * u64::from(pid))
    }
}

/// One pid's fake `/proc/<pid>/maps`.
#[derive(Clone)]
enum Maps {
    Missing,
    Text {
        bytes: Vec<u8>,
        chunk: usize,
        fail_after: Option<usize>,
    },
}

/// A deterministic population: sizes, line counts and short-read sizes
/// vary by pid; some pids are gone, some fail mid-read.
fn world(pids: &[u32]) -> BTreeMap<u32, Maps> {
    pids.iter()
        .map(|&pid| {
            let maps = if pid % 11 == 3 {
                Maps::Missing
            } else {
                let lines = 1 + (pid as usize * 7) % 13;
                let mut bytes = Vec::new();
                for line in 0..lines as u64 {
                    let start = 0x7f00_0000_0000 + u64::from(pid) * 0x10_0000 + line * 0x1000;
                    bytes.extend_from_slice(
                        format!(
                            "{start:x}-{:x} r-xp {:08x} 08:01 {} /usr/lib/libp{pid}-{line}.so\n",
                            start + 0x1000,
                            line * 0x1000,
                            1000 + u64::from(pid)
                        )
                        .as_bytes(),
                    );
                }
                Maps::Text {
                    chunk: 7 + (pid as usize * 13) % 97,
                    fail_after: (pid % 17 == 5).then_some(1 + (pid as usize % 3)),
                    bytes,
                }
            };
            (pid, maps)
        })
        .collect()
}

struct FakeReader {
    bytes: Vec<u8>,
    offset: usize,
    chunk: usize,
    reads: usize,
    fail_after: Option<usize>,
    served: &'static AtomicU64,
}

impl Read for FakeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.fail_after == Some(self.reads) {
            return Err(std::io::Error::from_raw_os_error(libc::EIO));
        }
        self.reads += 1;
        let n = self
            .chunk
            .min(buf.len())
            .min(self.bytes.len() - self.offset);
        buf[..n].copy_from_slice(&self.bytes[self.offset..self.offset + n]);
        self.offset += n;
        self.served.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

type Results = Vec<(u32, Result<Vec<MapEntry>, String>)>;

struct Run {
    results: Results,
    state: MapsSweepBudgetState,
    threads: usize,
    served: u64,
}

/// One sweep over `world` with `shards` shards (1 = the serial path),
/// against the budget `make` builds.
fn run(
    world: &BTreeMap<u32, Maps>,
    shards: usize,
    limits: MapsReadLimits,
    broken_clock: &HashSet<u32>,
    make: &dyn Fn() -> CaptureWorkBudget,
) -> Run {
    let served: &'static AtomicU64 = Box::leak(Box::new(AtomicU64::new(0)));
    let threads = Mutex::new(HashSet::new());
    let pids: Vec<u32> = world.keys().copied().collect();
    let open = |pid: u32| -> std::io::Result<FakeReader> {
        CURRENT.with(|current| current.set(pid));
        threads.lock().unwrap().insert(std::thread::current().id());
        match &world[&pid] {
            Maps::Missing => Err(std::io::Error::from_raw_os_error(libc::ENOENT)),
            Maps::Text {
                bytes,
                chunk,
                fail_after,
            } => Ok(FakeReader {
                bytes: bytes.clone(),
                offset: 0,
                chunk: *chunk,
                reads: 0,
                fail_after: *fail_after,
                served,
            }),
        }
    };
    let now = clock(broken_clock);
    let mut budget = make();
    let mut results = Vec::new();
    sweep_maps(
        &pids,
        &mut budget,
        shards,
        limits,
        &open,
        &now,
        &mut |pid, result| results.push((pid, result)),
    );
    let threads = threads.lock().unwrap().len();
    Run {
        results,
        state: budget.maps_sweep_state_for_test(),
        threads,
        served: served.load(Ordering::Relaxed),
    }
}

/// Serial against every shard count from 2 to 5 (5 > the pid count's
/// natural split for some lists), for one budget shape: equal results in
/// pid order and an equal final budget state.
fn assert_equivalent(
    world: &BTreeMap<u32, Maps>,
    limits: MapsReadLimits,
    broken_clock: &HashSet<u32>,
    make: &dyn Fn() -> CaptureWorkBudget,
    what: &str,
) -> Results {
    let serial = run(world, 1, limits, broken_clock, make);
    assert_eq!(serial.threads, 1, "{what}: serial is one thread");
    for shards in 2..=5 {
        let sharded = run(world, shards, limits, broken_clock, make);
        assert_eq!(
            sharded.results.len(),
            world.len(),
            "{what}: one result per pid ({shards} shards)"
        );
        assert_eq!(
            sharded.results, serial.results,
            "{what}: results ({shards} shards)"
        );
        assert_eq!(
            sharded.state, serial.state,
            "{what}: budget state ({shards} shards)"
        );
    }
    serial.results
}

fn pids(n: u32) -> Vec<u32> {
    (1..=n).map(|i| 100 + i * 3).collect()
}

fn snapshot_len(maps: &Maps) -> u64 {
    match maps {
        Maps::Missing => 0,
        Maps::Text { bytes, .. } => bytes.len() as u64,
    }
}

fn legacy(total_bytes: u64) -> impl Fn() -> CaptureWorkBudget {
    move || {
        CaptureWorkBudget::new(ScanLimits {
            per_object_bytes: 1 << 20,
            total_bytes,
        })
    }
}

fn reasons(results: &Results) -> Vec<&str> {
    results
        .iter()
        .filter_map(|(_, result)| result.as_ref().err().map(String::as_str))
        .collect()
}

#[test]
fn shard_ranges_cover_every_index_once_in_order() {
    for len in 0..40 {
        for shards in 1..=6 {
            let ranges = shard_ranges(len, shards);
            assert!(!ranges.is_empty());
            assert!(ranges.len() <= shards.max(1));
            let flat: Vec<usize> = ranges.iter().cloned().flatten().collect();
            assert_eq!(
                flat,
                (0..len).collect::<Vec<_>>(),
                "len {len} shards {shards}"
            );
            let sizes: Vec<usize> = ranges.iter().map(ExactSizeIterator::len).collect();
            let (min, max) = (sizes.iter().min().unwrap(), sizes.iter().max().unwrap());
            assert!(max - min <= 1, "balanced: {sizes:?}");
        }
    }
}

#[test]
fn shard_count_is_coarse_and_capped() {
    assert_eq!(shard_count(4096, 1), 1);
    assert_eq!(shard_count(4096, 2), 2);
    assert_eq!(shard_count(4096, 4), 4);
    assert_eq!(shard_count(4096, 64), MAX_SHARD_THREADS);
    assert_eq!(shard_count(MIN_PIDS_PER_SHARD * 2 - 1, 4), 1);
    assert_eq!(shard_count(MIN_PIDS_PER_SHARD * 2, 4), 2);
    assert_eq!(shard_count(MIN_PIDS_PER_SHARD * 3, 4), 3);
    assert_eq!(shard_count(0, 4), 1);
    assert_eq!(shard_count(10, 0), 1);
}

#[test]
fn the_shard_knob_parses_like_the_proof_stat_knob() {
    assert_eq!(parse_thread_knob(None, 4), None);
    assert_eq!(parse_thread_knob(Some("0"), 4), Some(1));
    assert_eq!(parse_thread_knob(Some("1"), 4), Some(1));
    assert_eq!(parse_thread_knob(Some(" 3 "), 4), Some(3));
    assert_eq!(parse_thread_knob(Some("+2"), 4), Some(2));
    assert_eq!(parse_thread_knob(Some("99"), 4), Some(4));
    assert_eq!(parse_thread_knob(Some("-1"), 4), None);
    assert_eq!(parse_thread_knob(Some("two"), 4), None);
    let (threads, note) = resolve_thread_knob(
        SHARD_THREADS_VAR,
        "shard",
        MAX_SHARD_THREADS,
        Some(std::ffi::OsStr::new("1")),
        2,
    );
    assert_eq!(threads, Some(1));
    assert_eq!(
        note.as_deref(),
        Some("p11scope: P11SCOPE_SHARD_THREADS=1 selects 1 shard thread")
    );
    let (threads, note) = resolve_thread_knob(
        SHARD_THREADS_VAR,
        "shard",
        MAX_SHARD_THREADS,
        Some(std::ffi::OsStr::new("x\x1b")),
        2,
    );
    assert_eq!(threads, None);
    assert_eq!(
        note.as_deref(),
        Some(
            "p11scope: ignoring invalid P11SCOPE_SHARD_THREADS=x\\u{1b}; using the default 2 shard threads"
        )
    );
    assert_eq!(
        resolve_thread_knob(SHARD_THREADS_VAR, "shard", 4, None, 2),
        (None, None)
    );
}

/// No ceiling: every shard count gives the serial results (reads, gone
/// pids, mid-read I/O errors) and the same I/O charge, and the shards
/// really run on more than one thread.
#[test]
fn sharded_sweep_equals_serial_without_a_ceiling() {
    let world = world(&pids(60));
    let results = assert_equivalent(
        &world,
        MapsReadLimits::LIVE,
        &HashSet::new(),
        &legacy(1 << 30),
        "unbounded",
    );
    assert!(results.iter().filter(|(_, r)| r.is_ok()).count() > 40);
    assert!(
        results
            .iter()
            .any(|(_, r)| r.as_ref().is_err_and(|e| e.contains("os error 2")))
    );
    assert!(
        results
            .iter()
            .any(|(_, r)| r.as_ref().is_err_and(|e| e.contains("os error 5")))
    );
    let sharded = run(
        &world,
        4,
        MapsReadLimits::LIVE,
        &HashSet::new(),
        &legacy(1 << 30),
    );
    assert!(
        sharded.threads > 1,
        "sharding must use more than one thread"
    );
}

/// The capture I/O ceiling (a byte total over all pids) crossed at every
/// offset of the sweep: inside each shard, on shard boundaries, exactly at
/// a snapshot's end (which the serial read still refuses: it needs one
/// more allowed byte to see end of file), and before the first byte.
#[test]
fn sharded_sweep_equals_serial_at_every_capture_io_ceiling() {
    let world = world(&pids(48));
    let total: u64 = world.values().map(snapshot_len).sum();
    let mut ends = Vec::new();
    let mut sum = 0;
    for maps in world.values() {
        sum += snapshot_len(maps);
        ends.push(sum);
    }
    let mut ceilings: Vec<u64> = (0..=total + 5).step_by(97).collect();
    for end in &ends {
        ceilings.extend([end.saturating_sub(1), *end, end + 1]);
    }
    let mut refused_mid_shard = false;
    for ceiling in ceilings {
        let results = assert_equivalent(
            &world,
            MapsReadLimits::LIVE,
            &HashSet::new(),
            &legacy(ceiling),
            &format!("capture I/O ceiling {ceiling}"),
        );
        let first = results
            .iter()
            .position(|(_, r)| r.as_ref().is_err_and(|e| e == IO_CEILING_REASON));
        refused_mid_shard |= first.is_some_and(|i| i > 12 && i % 12 != 0);
    }
    assert!(refused_mid_shard, "the ceiling must land inside a shard");
}

/// A shard reads no more than its share of the capture I/O that was left
/// when the sweep began, plus one chunk: past the ceiling it stops.
#[test]
fn a_shard_stops_reading_once_the_capture_io_is_spent() {
    let world = world(&pids(48));
    let ceiling = 600;
    let serial = run(
        &world,
        1,
        MapsReadLimits::LIVE,
        &HashSet::new(),
        &legacy(ceiling),
    );
    assert_eq!(serial.served, ceiling);
    for shards in 2..=4 {
        let sharded = run(
            &world,
            shards,
            MapsReadLimits::LIVE,
            &HashSet::new(),
            &legacy(ceiling),
        );
        assert!(
            sharded.served <= ceiling * shards as u64,
            "{shards} shards read {} bytes",
            sharded.served
        );
    }
}

/// The per-snapshot byte and entry ceilings on pids in the middle of a
/// shard: the same refusals, and the same bytes charged for the refused
/// reads.
#[test]
fn sharded_sweep_equals_serial_at_snapshot_byte_and_entry_ceilings() {
    let world = world(&pids(48));
    for max_bytes in [60, 300, 700] {
        let limits = MapsReadLimits {
            max_bytes,
            max_entries: MapsReadLimits::LIVE.max_entries,
            chunk: 64,
        };
        let results = assert_equivalent(
            &world,
            limits,
            &HashSet::new(),
            &legacy(1 << 30),
            &format!("max_bytes {max_bytes}"),
        );
        assert!(reasons(&results).contains(&MAPS_CEILING_REASON));
    }
    for max_entries in [1, 4, 9] {
        let limits = MapsReadLimits {
            max_bytes: MapsReadLimits::LIVE.max_bytes,
            max_entries,
            chunk: 50,
        };
        let results = assert_equivalent(
            &world,
            limits,
            &HashSet::new(),
            &legacy(1 << 30),
            &format!("max_entries {max_entries}"),
        );
        assert!(reasons(&results).contains(&MAPS_ENTRY_CEILING_REASON));
    }
}

/// A deadline crossed at every pid of the sweep: the serial sweep refuses
/// from the first pid read at or after it (reporting the reason once, on
/// that pid) and every later one; the shards give exactly that.
#[test]
fn sharded_sweep_equals_serial_at_every_deadline() {
    let world = world(&pids(48));
    let pids: Vec<u32> = world.keys().copied().collect();
    let mut deadlines: Vec<u64> = pids.iter().map(|pid| T0 + 10 * u64::from(*pid)).collect();
    deadlines.extend(pids.iter().map(|pid| T0 + 10 * u64::from(*pid) + 5));
    deadlines.push(T0);
    for deadline in deadlines {
        let make = move || {
            let mut budget = legacy(1 << 30)();
            budget.set_deadline(Some(deadline));
            budget
        };
        let results = assert_equivalent(
            &world,
            MapsReadLimits::LIVE,
            &HashSet::new(),
            &make,
            &format!("deadline {deadline}"),
        );
        let refused: Vec<u32> = results
            .iter()
            .filter(|(_, r)| r.as_ref().is_err_and(|e| e == SCAN_DEADLINE_REASON))
            .map(|(pid, _)| *pid)
            .collect();
        let late = pids
            .iter()
            .filter(|pid| {
                T0 + 10 * u64::from(**pid) >= deadline && !matches!(world[pid], Maps::Missing)
            })
            .count();
        assert_eq!(refused.len(), late, "deadline {deadline}");
    }
}

/// A clock that fails on one pid mid-shard stops the sweep there with the
/// clock reason, in both paths.
#[test]
fn sharded_sweep_equals_serial_when_the_clock_fails_mid_shard() {
    let world = world(&pids(48));
    let broken: HashSet<u32> = [world.keys().nth(20).copied().unwrap()].into();
    let make = || {
        let mut budget = legacy(1 << 30)();
        budget.set_deadline(Some(u64::MAX));
        budget
    };
    let results = assert_equivalent(&world, MapsReadLimits::LIVE, &broken, &make, "clock");
    assert!(reasons(&results).contains(&SCAN_CLOCK_REASON));
}

fn inventory_budget(window_io: u64, deadline: u64, scan: bool) -> CaptureWorkBudget {
    let limits = InventoryDiscoveryLimits::new(
        window_io,
        InventoryWindowLimits::new(window_io, 1 << 20, 64, 1 << 16, 64).unwrap(),
        InventoryRetainedLimits::new(16, 16, 16, 4, 4, 64 * 1024).unwrap(),
    )
    .unwrap();
    let mut budget = CaptureWorkBudget::for_inventory(limits);
    if scan {
        let token = budget.begin_window(WindowId::new(1), deadline).unwrap();
        budget.checkpoint(token).unwrap();
    }
    budget
}

/// Inventory policy: the window's I/O ceiling sets a sticky stop (with
/// the window's stop reason and exhaustion count), and the window deadline
/// applies, crossed inside a shard; both paths agree on all of it.
#[test]
fn sharded_sweep_equals_serial_under_an_inventory_window() {
    let world = world(&pids(48));
    let total: u64 = world.values().map(snapshot_len).sum();
    let pids: Vec<u32> = world.keys().copied().collect();
    for window_io in [1, total / 3, total / 2 + 7, total + 1, total * 2] {
        for deadline in [
            T0,
            T0 + 10 * u64::from(pids[17]) + 1,
            T0 + 10 * u64::from(pids[40]),
            u64::MAX,
        ] {
            let make = move || inventory_budget(window_io, deadline, true);
            assert_equivalent(
                &world,
                MapsReadLimits::LIVE,
                &HashSet::new(),
                &make,
                &format!("inventory io {window_io} deadline {deadline}"),
            );
        }
    }
    // No active scan: every read is refused at the I/O allowance, with no
    // sticky stop, in both paths.
    let results = assert_equivalent(
        &world,
        MapsReadLimits::LIVE,
        &HashSet::new(),
        &|| inventory_budget(total, u64::MAX, false),
        "inventory without a scan",
    );
    assert!(results.iter().all(|(_, r)| r.is_err()));
}

/// A budget already stopped before the sweep refuses every opened pid
/// with that reason, in both paths, and reports nothing new.
#[test]
fn sharded_sweep_equals_serial_on_an_already_stopped_budget() {
    let world = world(&pids(30));
    let make = || {
        let mut budget = legacy(1 << 30)();
        budget.set_deadline(Some(0));
        assert!(budget.check_deadline_now().is_some());
        budget
    };
    let results = assert_equivalent(
        &world,
        MapsReadLimits::LIVE,
        &HashSet::new(),
        &make,
        "stopped",
    );
    assert!(results.iter().all(|(_, r)| r.is_err()));
}

/// A shard whose thread dies is read again by the calling thread: the
/// sweep still equals the serial one.
#[test]
fn a_panicking_shard_is_read_again_on_the_calling_thread() {
    let world = world(&pids(40));
    let caller = std::thread::current().id();
    let pids: Vec<u32> = world.keys().copied().collect();
    let open = |pid: u32| -> std::io::Result<std::io::Cursor<Vec<u8>>> {
        CURRENT.with(|current| current.set(pid));
        assert_eq!(std::thread::current().id(), caller, "a shard thread fails");
        match &world[&pid] {
            Maps::Missing => Err(std::io::Error::from_raw_os_error(libc::ENOENT)),
            Maps::Text { bytes, .. } => Ok(std::io::Cursor::new(bytes.clone())),
        }
    };
    let working = HashSet::new();
    let now = clock(&working);
    let mut serial = Vec::new();
    let mut budget = legacy(1500)();
    sweep_maps(
        &pids,
        &mut budget,
        1,
        MapsReadLimits::LIVE,
        &open,
        &now,
        &mut |pid, r| {
            serial.push((pid, r));
        },
    );
    let serial_state = budget.maps_sweep_state_for_test();
    let mut sharded = Vec::new();
    let mut budget = legacy(1500)();
    sweep_maps(
        &pids,
        &mut budget,
        3,
        MapsReadLimits::LIVE,
        &open,
        &now,
        &mut |pid, r| {
            sharded.push((pid, r));
        },
    );
    assert_eq!(sharded, serial);
    assert_eq!(budget.maps_sweep_state_for_test(), serial_state);
}

/// The legacy capture I/O ceiling does not stick, so a replay can stop
/// early on it while its shard read on: crossed together with a deadline
/// (and a failing clock, and the snapshot ceilings), the sharded sweep is
/// still the serial one.
#[test]
fn sharded_sweep_equals_serial_at_a_legacy_io_ceiling_with_a_deadline() {
    let world = world(&pids(40));
    let pids: Vec<u32> = world.keys().copied().collect();
    let total: u64 = world.values().map(snapshot_len).sum();
    let tight = MapsReadLimits {
        max_bytes: 300,
        max_entries: 4,
        chunk: 64,
    };
    for broken in [HashSet::new(), [pids[27]].into()] {
        for io in (0..=total + 1).step_by(usize::try_from(total / 12).unwrap()) {
            for pid in pids.iter().step_by(8) {
                let deadline = T0 + 10 * u64::from(*pid) + 5;
                let make = move || {
                    let mut budget = legacy(io)();
                    budget.set_deadline(Some(deadline));
                    budget
                };
                for limits in [MapsReadLimits::LIVE, tight] {
                    assert_equivalent(
                        &world,
                        limits,
                        &broken,
                        &make,
                        &format!("io {io} deadline {deadline} {limits:?}"),
                    );
                }
            }
        }
    }
}
