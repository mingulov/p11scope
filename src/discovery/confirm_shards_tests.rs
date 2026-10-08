//! SPDX-License-Identifier: GPL-3.0-or-later
//! C7 A5: the sharded confirmation is the serial one, attribution for
//! attribution and charge for charge, at every ceiling.

use super::*;
use crate::discovery::caller_registry::ExeIdentity;
use crate::discovery::identity::{ExaminedObject, FileIdentity, MappedFile, PinnedObjectId};
use crate::discovery::scan::{
    InventoryDiscoveryLimits, InventoryRetainedLimits, InventoryWindowLimits, ScanLimits, WindowId,
    read_maps_or_refuse,
};
use crate::discovery::sweep_attribution::{ObjectChecks, RANGE_NOT_MAPPED, attribute_unselected};
use p11scope_manifest::maps::Device;
use std::cell::Cell;
use std::collections::{BTreeMap, HashSet};
use std::sync::Mutex;

const PROVIDER: u64 = 7_001;
const LIBC: u64 = 7_002;
const OBJECT: PinnedObjectId = PinnedObjectId(1);
const T0: u64 = 1_000_000;

fn key(inode: u64) -> ObjectKey {
    ObjectKey {
        device: Device { major: 8, minor: 1 },
        inode,
    }
}

fn vm_file(inode: u64) -> FileIdentity {
    FileIdentity {
        dev: 37,
        ino: inode,
    }
}

fn line(start: u64, perms: &str, inode: u64, path: &str) -> String {
    format!(
        "{start:x}-{:x} {perms} 00000000 08:01 {inode} {path}\n",
        start + 0x1000
    )
}

fn object_lines(base: u64, inode: u64, path: &str) -> String {
    line(base, "r--p", inode, path) + &line(base + 0x1000, "r-xp", inode, path)
}

/// One pid's scripted world: its phase-1 snapshot, what its confirmation
/// re-read shows, and how its operating-system reads answer.
#[derive(Clone)]
struct Script {
    phase_one: Vec<MapEntry>,
    confirm_maps: Option<String>,
}

fn kind(pid: u32) -> u32 {
    pid % 7
}

/// The maps text of `pid` (phase 1 and, unless scripted otherwise, the
/// confirmation): callers map the provider, idle pids map libc (examined)
/// and some an unexamined library.
fn maps_text(pid: u32) -> String {
    let mut text = object_lines(0x2000_0000, LIBC, "/usr/lib/libc.so.6");
    if kind(pid) <= 3 {
        text += &object_lines(0x1000_0000, PROVIDER, "/usr/lib/softhsm/libsofthsm2.so");
    }
    if kind(pid) == 5 {
        let inode = 8_000 + u64::from(pid);
        text += &object_lines(0x3000_0000, inode, &format!("/usr/lib/libu{inode}.so"));
    }
    text
}

fn world(n: u32) -> BTreeMap<u32, Script> {
    (1..=n)
        .map(|i| {
            let pid = 200 + i * 3;
            let text = maps_text(pid);
            let confirm_maps = match pid % 11 {
                // The provider unloaded before the confirmation.
                4 => Some(object_lines(0x2000_0000, LIBC, "/usr/lib/libc.so.6")),
                // The maps file does not open.
                9 => None,
                _ => Some(text.clone()),
            };
            let phase_one = p11scope_manifest::maps::parse_maps(text.as_bytes()).unwrap();
            (
                pid,
                Script {
                    phase_one,
                    confirm_maps,
                },
            )
        })
        .collect()
}

struct Checks;

impl ObjectChecks for Checks {
    fn nonunique_inodes(&self, _: PinnedObjectId) -> Result<Option<&'static str>, String> {
        Ok(None)
    }
    fn unchanged(&self, _: PinnedObjectId) -> Result<bool, String> {
        Ok(true)
    }
    fn mapped_identity(&self, _: PinnedObjectId) -> Result<MappedFile, String> {
        Ok(MappedFile {
            identity: vm_file(PROVIDER),
            fs_magic: None,
        })
    }
}

fn index() -> KnownKeyIndex {
    let examined = [ExaminedObject {
        key: key(LIBC),
        identity: vm_file(LIBC),
        key_is_identity: false,
    }];
    KnownKeyIndex::build(
        [(key(PROVIDER), Some(OBJECT))],
        &BTreeMap::from([(key(PROVIDER), OBJECT)]),
        examined,
        &Checks,
    )
    .0
}

/// The scripted `/proc`: a fresh one per probe call, as in production.
struct FakeIo<'w> {
    world: &'w BTreeMap<u32, Script>,
    exe_reads: Cell<u32>,
    pid: Cell<u32>,
    threads: &'w Mutex<HashSet<std::thread::ThreadId>>,
}

impl ConfirmIo for FakeIo<'_> {
    type Pin = u32;

    fn mapped_file(&mut self, pid: u32, start: u64, _end: u64) -> Result<FileIdentity, String> {
        self.threads
            .lock()
            .unwrap()
            .insert(std::thread::current().id());
        match (pid + (start >> 24) as u32) % 13 {
            0 => Err(RANGE_NOT_MAPPED.into()),
            1 => Err("Operation not permitted (os error 1)".into()),
            // A btrfs-style collision: the same key, another file.
            2 => Ok(vm_file(99)),
            _ => {
                let inode = match start >> 28 {
                    1 => PROVIDER,
                    2 => LIBC,
                    _ => 8_000 + u64::from(pid),
                };
                Ok(vm_file(inode))
            }
        }
    }

    fn open(&mut self, pid: u32) -> Result<u32, String> {
        self.pid.set(pid);
        if pid % 17 == 6 {
            Err("No such process (os error 3)".into())
        } else {
            Ok(pid)
        }
    }

    fn start_time(&self, pin: &u32) -> Option<u64> {
        (pin % 29 != 5).then_some(u64::from(*pin) * 7)
    }

    fn still_the_same(&self, pin: &u32) -> bool {
        pin % 31 != 7
    }

    fn exe(&self, pid: u32) -> Option<ExeIdentity> {
        let reads = self.exe_reads.get();
        self.exe_reads.set(reads + 1);
        if pid % 23 == 3 {
            return None;
        }
        Some(ExeIdentity {
            dev: 1,
            // An exec between the two reads.
            ino: if pid % 19 == 8 { u64::from(reads) } else { 100 },
            mtime_secs: 10,
            mtime_nanos: 0,
            path: Some("/usr/bin/caller".into()),
        })
    }

    fn maps(&mut self, pid: u32, budget: &mut CaptureWorkBudget) -> Result<Vec<MapEntry>, String> {
        let file = self.open_maps(pid).map_err(|error| error.to_string())?;
        read_maps_or_refuse(file, budget, || self.maps_now())
    }

    fn gone(&self, pid: u32) -> bool {
        pid.is_multiple_of(2)
    }
}

impl ShardableIo for FakeIo<'_> {
    type Maps = std::io::Cursor<Vec<u8>>;

    fn open_maps(&mut self, pid: u32) -> std::io::Result<Self::Maps> {
        self.pid.set(pid);
        match &self.world[&pid].confirm_maps {
            Some(text) => Ok(std::io::Cursor::new(text.clone().into_bytes())),
            None => Err(std::io::Error::from_raw_os_error(libc::ENOENT)),
        }
    }

    /// One clock reading per pid: the same on any thread, in any order.
    fn maps_now(&self) -> Option<u64> {
        Some(T0 + 10 * u64::from(self.pid.get()))
    }
}

type State = (crate::discovery::scan::MapsSweepBudgetState, u64);

struct Outcome {
    attribution: SweepAttribution,
    state: State,
    threads: usize,
}

fn run(
    world: &BTreeMap<u32, Script>,
    shards: usize,
    make_budget: &dyn Fn() -> CaptureWorkBudget,
) -> Outcome {
    let threads = Mutex::new(HashSet::new());
    let make_io = || FakeIo {
        world,
        exe_reads: Cell::new(0),
        pid: Cell::new(0),
        threads: &threads,
    };
    let sweep: Vec<(u32, Vec<MapEntry>)> = world
        .iter()
        .map(|(pid, script)| (*pid, script.phase_one.clone()))
        .collect();
    // A few pids were deep-scanned, a few had no phase-1 snapshot.
    let selected: BTreeSet<u32> = sweep
        .iter()
        .map(|(pid, _)| *pid)
        .filter(|pid| pid % 41 == 0)
        .collect();
    let unavailable: BTreeSet<u32> = sweep
        .iter()
        .map(|(pid, _)| *pid)
        .filter(|pid| pid % 43 == 1)
        .collect();
    let index = index();
    let mut budget = make_budget();
    let policy = SegmentPolicy::from_headroom(64, 4, sweep.len());
    let owner = ReservationOwner::new(policy);
    let attribution = attribute_unselected_with_policy(
        &sweep,
        &unavailable,
        &selected,
        &index,
        &mut budget,
        policy,
        &owner,
        shards,
        &make_io,
    );
    assert_eq!(owner.state_for_test().0, [0; 4]);
    let threads = threads.lock().unwrap().len();
    Outcome {
        attribution,
        state: budget.confirm_state_for_test(),
        threads,
    }
}

fn assert_equivalent(
    world: &BTreeMap<u32, Script>,
    make_budget: &dyn Fn() -> CaptureWorkBudget,
    what: &str,
) -> SweepAttribution {
    let serial = run(world, 1, make_budget);
    for shards in 2..=5 {
        let sharded = run(world, shards, make_budget);
        assert_eq!(
            sharded.attribution, serial.attribution,
            "{what}: attribution ({shards} shards)"
        );
        assert_eq!(
            sharded.state, serial.state,
            "{what}: budget ({shards} shards)"
        );
    }
    serial.attribution
}

fn legacy(total_bytes: u64, work: u64) -> impl Fn() -> CaptureWorkBudget {
    move || {
        let mut budget = CaptureWorkBudget::new(ScanLimits {
            per_object_bytes: 1 << 20,
            total_bytes,
        });
        budget.set_work_ceiling_for_test(work);
        budget
    }
}

/// The scripted world exercises every branch the comparison should see.
#[test]
fn the_scripted_world_reaches_every_outcome() {
    let world = world(120);
    let outcome = run(&world, 1, &legacy(u64::MAX, u64::MAX));
    let attribution = outcome.attribution;
    assert!(attribution.members.len() > 10, "{attribution:?}");
    assert!(attribution.losses.len() >= 4, "{:?}", attribution.losses);
    assert!(!attribution.exited.is_empty());
    assert!(!attribution.unexamined.is_empty());
    assert!(attribution.unavailable > 0);
    assert!(attribution.probed > attribution.members.len());
}

/// No ceiling: every shard count gives the serial attribution and budget,
/// and the proofs are read on more than one thread.
#[test]
fn sharded_confirmation_equals_serial_without_a_ceiling() {
    let world = world(120);
    assert_equivalent(&world, &legacy(u64::MAX, u64::MAX), "unbounded");
    let sharded = run(&world, 4, &legacy(u64::MAX, u64::MAX));
    assert!(sharded.threads > 1, "the proofs must be read on the shards");
}

/// The work ceiling (one unit per proof range, charged first) crossed at
/// every point of the stage, inside shards and on their boundaries.
#[test]
fn sharded_confirmation_equals_serial_at_every_work_ceiling() {
    let world = world(120);
    let unbounded = run(&world, 1, &legacy(u64::MAX, u64::MAX));
    let total = unbounded.state.1;
    assert!(total > 100, "{total}");
    let mut budget_losses = 0;
    for ceiling in (0..=total + 2).step_by(3) {
        let attribution = assert_equivalent(
            &world,
            &legacy(u64::MAX, ceiling),
            &format!("work ceiling {ceiling}"),
        );
        budget_losses += attribution
            .losses
            .get(&crate::discovery::sweep_attribution::AttributionLoss::Budget)
            .copied()
            .unwrap_or(0);
    }
    assert!(budget_losses > 0, "the ceiling must cost confirmations");
}

/// The capture I/O ceiling on the confirmation re-reads, crossed at every
/// point of the stage.
#[test]
fn sharded_confirmation_equals_serial_at_every_capture_io_ceiling() {
    let world = world(120);
    let unbounded = run(&world, 1, &legacy(u64::MAX, u64::MAX));
    let total = unbounded.state.0.attempted_io_bytes;
    assert!(total > 1_000, "{total}");
    for ceiling in (0..=total + 1)
        .step_by(211)
        .chain([total - 1, total, total + 1])
    {
        assert_equivalent(
            &world,
            &legacy(ceiling, u64::MAX),
            &format!("I/O ceiling {ceiling}"),
        );
    }
}

/// A deadline crossed at every pid of the stage.
#[test]
fn sharded_confirmation_equals_serial_at_every_deadline() {
    let world = world(90);
    let mut refused = 0;
    for pid in world.keys().copied().step_by(2) {
        for offset in [0, 5] {
            let deadline = T0 + 10 * u64::from(pid) + offset;
            let make = move || {
                let mut budget = legacy(u64::MAX, u64::MAX)();
                budget.set_deadline(Some(deadline));
                budget
            };
            let attribution = assert_equivalent(&world, &make, &format!("deadline {deadline}"));
            refused += attribution
                .losses
                .get(&crate::discovery::sweep_attribution::AttributionLoss::Budget)
                .copied()
                .unwrap_or(0);
        }
    }
    assert!(refused > 0, "the deadline must refuse confirmations");
}

/// Inventory policy: window I/O and work allowances and the window
/// deadline, each crossed inside a shard.
#[test]
fn sharded_confirmation_equals_serial_under_an_inventory_window() {
    let world = world(90);
    let unbounded = run(&world, 1, &legacy(u64::MAX, u64::MAX));
    let (io, work) = (unbounded.state.0.attempted_io_bytes, unbounded.state.1);
    let pids: Vec<u32> = world.keys().copied().collect();
    for (window_io, window_work, deadline) in [
        (io * 2, work * 2, u64::MAX),
        (io / 2, work * 2, u64::MAX),
        (io * 2, work / 2, u64::MAX),
        (io * 2, work * 2, T0 + 10 * u64::from(pids[50]) + 1),
        (io / 3, work / 3, T0 + 10 * u64::from(pids[70])),
    ] {
        let make = move || {
            let limits = InventoryDiscoveryLimits::new(
                window_io.min(1 << 16),
                InventoryWindowLimits::new(window_io, window_work, 64, 1 << 16, 64).unwrap(),
                InventoryRetainedLimits::new(16, 16, 16, 4, 4, 64 * 1024).unwrap(),
            )
            .unwrap();
            let mut budget = CaptureWorkBudget::for_inventory(limits);
            let token = budget.begin_window(WindowId::new(1), deadline).unwrap();
            budget.checkpoint(token).unwrap();
            budget
        };
        assert_equivalent(
            &world,
            &make,
            &format!("inventory io {window_io} work {window_work} deadline {deadline}"),
        );
    }
}

/// Root, through the production `/proc` reads: real `sleep` children whose
/// libc text is a matched key. Every child is pinned, re-read and proven
/// on the shards and replayed; the result is the serial production probe's,
/// member for member (start times, exe identities, paths).
#[test]
#[ignore = "root (map_files): proves real children's ranges"]
fn privileged_sharded_confirmation_equals_the_serial_production_probe() {
    use crate::discovery::sweep_attribution::{OsConfirmIo, OsMemberProbe};
    struct Kill(Vec<std::process::Child>);
    impl Drop for Kill {
        fn drop(&mut self) {
            for child in &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
    let children = Kill(
        (0..24)
            .map(|_| {
                std::process::Command::new("sleep")
                    .arg("60")
                    .spawn()
                    .unwrap()
            })
            .collect(),
    );
    // Exec-settle (dev-flake): a pre-exec child still maps this test binary
    // (including its libc), so a fixed sleep cannot prove readiness. Only
    // read maps once every child exec'd sleep AND mapped libc text — the
    // condition this sweep actually consumes below. Bounded; on timeout
    // FAILS LOUD naming the child, never silently proceeds.
    let self_exe = std::env::current_exe().unwrap();
    for child in &children.0 {
        let pid = child.id();
        let exe = format!("/proc/{pid}/exe");
        let maps_path = format!("/proc/{pid}/maps");
        let mut settled = false;
        let mut evidence = String::from("no read attempted");
        for _ in 0..200 {
            let image = std::fs::read_link(&exe).ok();
            let execed = image.as_ref().is_some_and(|image| image != &self_exe);
            let libc_mapped = std::fs::read(&maps_path)
                .ok()
                .and_then(|text| p11scope_manifest::maps::parse_maps(&text).ok())
                .is_some_and(|entries| {
                    entries.iter().any(|entry| {
                        entry.permissions[2] == b'x'
                            && entry
                                .raw_path
                                .as_deref()
                                .is_some_and(|path| path.windows(4).any(|w| w == b"libc"))
                    })
                });
            if execed && libc_mapped {
                settled = true;
                break;
            }
            evidence = format!("exe={image:?} libc_mapped={libc_mapped}");
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(settled, "sleep child {pid} never settled; last {evidence}");
    }
    let sweep: Vec<(u32, Vec<MapEntry>)> = children
        .0
        .iter()
        .map(|child| {
            let text = std::fs::read(format!("/proc/{}/maps", child.id())).unwrap();
            (
                child.id(),
                p11scope_manifest::maps::parse_maps(&text).unwrap(),
            )
        })
        .collect();
    let (pid, entries) = &sweep[0];
    let libc_text = entries
        .iter()
        .find(|entry| {
            entry.permissions[2] == b'x'
                && entry
                    .raw_path
                    .as_deref()
                    .is_some_and(|path| path.windows(4).any(|w| w == b"libc"))
        })
        .expect("sleep maps libc text");
    let identity =
        crate::discovery::identity::map_files_identity(*pid, libc_text.start, libc_text.end)
            .unwrap();
    struct Held(FileIdentity);
    impl ObjectChecks for Held {
        fn nonunique_inodes(&self, _: PinnedObjectId) -> Result<Option<&'static str>, String> {
            Ok(None)
        }
        fn unchanged(&self, _: PinnedObjectId) -> Result<bool, String> {
            Ok(true)
        }
        fn mapped_identity(&self, _: PinnedObjectId) -> Result<MappedFile, String> {
            Ok(MappedFile {
                identity: self.0,
                fs_magic: None,
            })
        }
    }
    let libc = ObjectKey::of(libc_text);
    let (index, _) = KnownKeyIndex::build(
        [(libc, Some(OBJECT))],
        &BTreeMap::from([(libc, OBJECT)]),
        [],
        &Held(identity),
    );
    let none = BTreeSet::new();
    let mut serial_budget = CaptureWorkBudget::default();
    let serial = attribute_unselected(
        &sweep,
        &none,
        &none,
        &index,
        &mut OsMemberProbe::default(),
        &mut serial_budget,
    );
    assert_eq!(serial.members.len(), sweep.len(), "{serial:?}");
    for shards in 2..=4 {
        let mut budget = CaptureWorkBudget::default();
        let sharded = attribute_unselected_sharded(
            &sweep,
            &none,
            &none,
            &index,
            &mut budget,
            shards,
            &OsConfirmIo::default,
        );
        assert_eq!(sharded, serial, "{shards} shards");
        assert_eq!(
            budget.confirm_state_for_test().1,
            serial_budget.confirm_state_for_test().1,
            "work charged ({shards} shards)"
        );
    }
}

/// A detailed budget's capture I/O ceiling refuses a maps re-read without
/// a sticky stop, before its proofs are charged, so a replay can spend
/// less work on a pid than its shard did: the shadow then stops on the work
/// ceiling at a later pid where the capture budget does not. Skewed so that
/// it happens: the first shard is I/O-heavy and work-light, the second
/// opens with a work-heavy caller and then idle examined pids. Every cell
/// still gives the serial attribution and budget (an uncovered pid is
/// confirmed live, not replayed from a short record).
#[test]
fn sharded_confirmation_equals_serial_when_a_replay_spends_less_than_its_shard() {
    const SOFTHSM: &str = "/usr/lib/softhsm/libsofthsm2.so";
    let anon: String = (0..300u64)
        .map(|i| {
            let start = 0x5000_0000 + i * 0x2000;
            format!("{start:x}-{:x} rw-p 00000000 00:00 0 \n", start + 0x1000)
        })
        .collect();
    let mut world = BTreeMap::new();
    for i in 0..8u32 {
        let pid = 1_001 + i * 4;
        let text: String = match i {
            0..4 => object_lines(0x1000_0000, PROVIDER, SOFTHSM) + &anon,
            4 => (0..40u64)
                .map(|r| line(0x1000_0000 + r * 0x2000, "r-xp", PROVIDER, SOFTHSM))
                .collect(),
            _ => (0..10u64)
                .map(|r| line(0x2000_0000 + r * 0x2000, "r-xp", LIBC, "/usr/lib/libc.so.6"))
                .collect(),
        };
        let phase_one = p11scope_manifest::maps::parse_maps(text.as_bytes()).unwrap();
        world.insert(
            pid,
            Script {
                phase_one,
                confirm_maps: Some(text),
            },
        );
    }
    let unbounded = run(&world, 1, &legacy(u64::MAX, u64::MAX));
    let (io, work) = (unbounded.state.0.attempted_io_bytes, unbounded.state.1);
    assert!(io > 30_000 && work > 40, "io {io} work {work}");
    for io_ceiling in (0..=io + 1).step_by(usize::try_from(io / 40).unwrap()) {
        for work_ceiling in 0..=work + 1 {
            assert_equivalent(
                &world,
                &legacy(io_ceiling, work_ceiling),
                &format!("io {io_ceiling} work {work_ceiling}"),
            );
        }
    }
}

/// D3a catches end-to-end speculation: every accepted pin must survive until
/// shared proof and the live final checks, after all segment preparations.
#[derive(Default)]
struct D3aEvents {
    events: Vec<(u32, &'static str)>,
    pins: BTreeSet<u32>,
    requests: Vec<(u32, u64, u64)>,
    peak_pins: usize,
    prepare_threads: HashSet<std::thread::ThreadId>,
    proof_threads: HashSet<std::thread::ThreadId>,
}

struct D3aPin {
    pid: u32,
    events: std::sync::Arc<Mutex<D3aEvents>>,
    file: Option<std::fs::File>,
}

impl Drop for D3aPin {
    fn drop(&mut self) {
        drop(self.file.take());
        let mut events = self.events.lock().unwrap();
        assert!(events.pins.remove(&self.pid));
        events.events.push((self.pid, "drop"));
    }
}

struct D3aIo<'w> {
    world: &'w BTreeMap<u32, Script>,
    events: std::sync::Arc<Mutex<D3aEvents>>,
    exe_reads: Cell<u32>,
    stale_idle: Option<u32>,
    bad_range: Option<u64>,
    changed_generation: bool,
    changed_exe: bool,
    fail_at: Option<(u32, &'static str)>,
    panic_at: Option<(u32, &'static str)>,
}

impl D3aIo<'_> {
    fn fails(&self, pid: u32, stage: &'static str) -> bool {
        assert_ne!(
            self.panic_at,
            Some((pid, stage)),
            "injected D3a worker cancellation"
        );
        self.fail_at == Some((pid, stage))
    }
}

impl ConfirmIo for D3aIo<'_> {
    type Pin = D3aPin;

    fn mapped_file(&mut self, pid: u32, start: u64, end: u64) -> Result<FileIdentity, String> {
        if self.fails(pid, "proof") {
            return Err("scripted proof unavailable".into());
        }
        let mut events = self.events.lock().unwrap();
        events.proof_threads.insert(std::thread::current().id());
        events.events.push((pid, "proof"));
        events.requests.push((pid, start, end));
        if self.stale_idle == Some(pid) && start == 0x2000_1000 {
            return Err(RANGE_NOT_MAPPED.into());
        }
        Ok(vm_file(if self.bad_range == Some(start) {
            99
        } else if start >> 28 == 1 {
            PROVIDER
        } else {
            LIBC
        }))
    }

    fn open(&mut self, pid: u32) -> Result<Self::Pin, String> {
        if self.fails(pid, "pin") {
            return Err("scripted pin unavailable".into());
        }
        let file = std::fs::File::open("/dev/null").unwrap();
        let mut events = self.events.lock().unwrap();
        assert!(events.pins.insert(pid), "a reread retained the old pin");
        events.peak_pins = events.peak_pins.max(events.pins.len());
        events.events.push((pid, "pin"));
        Ok(D3aPin {
            pid,
            events: self.events.clone(),
            file: Some(file),
        })
    }

    fn start_time(&self, pin: &Self::Pin) -> Option<u64> {
        let fails = self.fails(pin.pid, "start");
        let mut events = self.events.lock().unwrap();
        assert!(events.pins.contains(&pin.pid));
        events.events.push((pin.pid, "start"));
        (!fails).then_some(u64::from(pin.pid))
    }

    fn still_the_same(&self, pin: &Self::Pin) -> bool {
        let mut events = self.events.lock().unwrap();
        assert!(events.pins.contains(&pin.pid));
        events.events.push((pin.pid, "same"));
        !self.changed_generation
    }

    fn exe(&self, pid: u32) -> Option<ExeIdentity> {
        let reads = self.exe_reads.get();
        self.exe_reads.set(reads + 1);
        if self.fails(pid, if reads == 0 { "before" } else { "after" }) {
            return None;
        }
        self.events
            .lock()
            .unwrap()
            .events
            .push((pid, if reads == 0 { "before" } else { "after" }));
        Some(ExeIdentity {
            dev: 1,
            ino: if self.changed_exe && reads > 0 {
                101
            } else {
                100
            },
            mtime_secs: 10,
            mtime_nanos: 0,
            path: None,
        })
    }

    fn maps(&mut self, pid: u32, budget: &mut CaptureWorkBudget) -> Result<Vec<MapEntry>, String> {
        let file = self.open_maps(pid).map_err(|error| error.to_string())?;
        read_maps_or_refuse(file, budget, || self.maps_now())
    }

    fn gone(&self, _pid: u32) -> bool {
        false
    }
}

impl ShardableIo for D3aIo<'_> {
    type Maps = std::io::Cursor<Vec<u8>>;

    fn open_maps(&mut self, pid: u32) -> std::io::Result<Self::Maps> {
        self.events
            .lock()
            .unwrap()
            .prepare_threads
            .insert(std::thread::current().id());
        if self.fails(pid, "maps") {
            return Err(std::io::Error::from_raw_os_error(libc::EACCES));
        }
        self.events.lock().unwrap().events.push((pid, "maps"));
        self.world[&pid]
            .confirm_maps
            .as_ref()
            .map(|text| std::io::Cursor::new(text.clone().into_bytes()))
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))
    }

    fn maps_now(&self) -> Option<u64> {
        Some(T0)
    }
}

fn d3a_caller_world(pids: &[u32]) -> BTreeMap<u32, Script> {
    pids.iter()
        .map(|&pid| {
            let text = object_lines(0x1000_0000, PROVIDER, "/usr/lib/softhsm/libsofthsm2.so");
            (
                pid,
                Script {
                    phase_one: p11scope_manifest::maps::parse_maps(text.as_bytes()).unwrap(),
                    confirm_maps: Some(text),
                },
            )
        })
        .collect()
}

#[test]
fn d3a_prepare_prove_finish_order() {
    let world = d3a_caller_world(&[1001, 1002]);
    let events = std::sync::Arc::new(Mutex::new(D3aEvents::default()));
    let make_io = || D3aIo {
        world: &world,
        events: events.clone(),
        exe_reads: Cell::new(0),
        stale_idle: None,
        bad_range: None,
        changed_generation: false,
        changed_exe: false,
        fail_at: None,
        panic_at: None,
    };
    let sweep: Vec<_> = world
        .iter()
        .map(|(&pid, script)| (pid, script.phase_one.clone()))
        .collect();
    let out = attribute_unselected_sharded(
        &sweep,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &index(),
        &mut legacy(u64::MAX, u64::MAX)(),
        1,
        &make_io,
    );
    assert_eq!(
        out.members
            .iter()
            .map(|member| member.pid)
            .collect::<Vec<_>>(),
        [1001, 1002]
    );
    let events = events.lock().unwrap();
    let first_proof = events
        .events
        .iter()
        .position(|(_, event)| *event == "proof")
        .unwrap();
    for pid in [1001, 1002] {
        assert!(
            events.events[..first_proof].contains(&(pid, "maps")),
            "proof preceded segment preparation: {:?}",
            events.events
        );
        let proof = events
            .events
            .iter()
            .position(|event| *event == (pid, "proof"))
            .unwrap();
        let after = events
            .events
            .iter()
            .position(|event| *event == (pid, "after"))
            .unwrap();
        let same = events
            .events
            .iter()
            .position(|event| *event == (pid, "same"))
            .unwrap();
        let start = events
            .events
            .iter()
            .position(|event| *event == (pid, "start"))
            .unwrap();
        let drop = events
            .events
            .iter()
            .position(|event| *event == (pid, "drop"))
            .unwrap();
        assert!(proof < after && after < same && same < start && start < drop);
    }
    assert!(events.pins.is_empty());
    assert_eq!(
        events.requests,
        [
            (1001, 0x1000_1000, 0x1000_2000),
            (1002, 0x1000_1000, 0x1000_2000)
        ]
    );
}

#[test]
fn d3a_promotions_charge_after_segment() {
    let mut world = d3a_caller_world(&[1001, 1002]);
    world.get_mut(&1001).unwrap().phase_one = p11scope_manifest::maps::parse_maps(
        object_lines(0x2000_0000, LIBC, "/usr/lib/libc.so.6").as_bytes(),
    )
    .unwrap();
    let events = std::sync::Arc::new(Mutex::new(D3aEvents::default()));
    let make_io = || D3aIo {
        world: &world,
        events: events.clone(),
        exe_reads: Cell::new(0),
        stale_idle: Some(1001),
        bad_range: None,
        changed_generation: false,
        changed_exe: false,
        fail_at: None,
        panic_at: None,
    };
    let sweep: Vec<_> = world
        .iter()
        .map(|(&pid, script)| (pid, script.phase_one.clone()))
        .collect();
    let mut budget = legacy(u64::MAX, 2)();
    let out = attribute_unselected_sharded(
        &sweep,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &index(),
        &mut budget,
        1,
        &make_io,
    );
    assert_eq!(
        out.members
            .iter()
            .map(|member| member.pid)
            .collect::<Vec<_>>(),
        [1002],
        "phase-D promotion stole a later segment charge: {out:?}"
    );
    assert_eq!(
        out.member_losses[&1001].0,
        crate::discovery::sweep_attribution::AttributionLoss::Budget
    );
    // A refused promotion leaves the original examined key unproven,
    // exactly as the existing lost-confirmation policy specifies.
    assert_eq!(out.unexamined_objects, BTreeSet::from([key(LIBC)]));
    assert_eq!(out.unexamined, BTreeMap::from([(1001, 1)]));
    assert_eq!(budget.confirm_state_for_test().1, 2);
    let events = events.lock().unwrap();
    let maps: Vec<_> = events
        .events
        .iter()
        .filter(|(_, event)| *event == "maps")
        .map(|(pid, _)| *pid)
        .collect();
    assert_eq!(maps, [1002, 1001]);
    assert!(events.pins.is_empty());
}

/// Catches selecting a header/remnant or accepting only one proved text VMA.
#[test]
fn d3a_requested_ranges_and_every_range() {
    use crate::discovery::sweep_attribution::AttributionLoss;
    let mut world = d3a_caller_world(&[1001, 1002]);
    let text = object_lines(0x1000_0000, PROVIDER, "/usr/lib/softhsm/libsofthsm2.so")
        + &line(
            0x1000_3000,
            "r-xp",
            PROVIDER,
            "/usr/lib/softhsm/libsofthsm2.so",
        )
        + &line(
            0x1000_4000,
            "rw-p",
            PROVIDER,
            "/usr/lib/softhsm/libsofthsm2.so",
        );
    world.get_mut(&1001).unwrap().phase_one =
        p11scope_manifest::maps::parse_maps(text.as_bytes()).unwrap();
    world.get_mut(&1001).unwrap().confirm_maps = Some(text);
    world.get_mut(&1002).unwrap().phase_one = p11scope_manifest::maps::parse_maps(
        line(
            0x1000_0000,
            "r--p",
            PROVIDER,
            "/usr/lib/softhsm/libsofthsm2.so",
        )
        .as_bytes(),
    )
    .unwrap();
    let sweep: Vec<_> = world
        .iter()
        .map(|(&pid, script)| (pid, script.phase_one.clone()))
        .collect();
    for shards in [1, 4] {
        let events = std::sync::Arc::new(Mutex::new(D3aEvents::default()));
        let make_io = || D3aIo {
            world: &world,
            events: events.clone(),
            exe_reads: Cell::new(0),
            stale_idle: None,
            bad_range: Some(0x1000_3000),
            changed_generation: false,
            changed_exe: false,
            fail_at: None,
            panic_at: None,
        };
        let mut budget = legacy(u64::MAX, u64::MAX)();
        let out = attribute_unselected_sharded(
            &sweep,
            &BTreeSet::new(),
            &BTreeSet::new(),
            &index(),
            &mut budget,
            shards,
            &make_io,
        );
        assert!(
            out.members.is_empty(),
            "one negative executable range cannot match: {out:?}"
        );
        assert_eq!(
            out.member_losses.keys().copied().collect::<Vec<_>>(),
            [1001]
        );
        assert_eq!(
            out.member_losses[&1001].0,
            AttributionLoss::IdentityMismatch
        );
        assert!(out.unexamined.is_empty());
        assert_eq!(out.probed, 1);
        assert_eq!(budget.confirm_state_for_test().1, 2);
        let events = events.lock().unwrap();
        assert_eq!(
            events.requests,
            [
                (1001, 0x1000_1000, 0x1000_2000),
                (1001, 0x1000_3000, 0x1000_4000)
            ]
        );
        assert!(!events.events.iter().any(|(pid, _)| *pid == 1002));
        assert!(events.pins.is_empty());
    }
}

/// Catches reusing speculative final identity answers after shared proof.
#[test]
fn d3a_live_final_checks_refuse_exec_and_generation_changes() {
    use crate::discovery::sweep_attribution::AttributionLoss;
    let world = d3a_caller_world(&[1001]);
    let sweep = vec![(1001, world[&1001].phase_one.clone())];
    for (generation, exe, want) in [
        (true, false, AttributionLoss::GenerationChanged),
        (false, true, AttributionLoss::ExecChanged),
    ] {
        let events = std::sync::Arc::new(Mutex::new(D3aEvents::default()));
        let make_io = || D3aIo {
            world: &world,
            events: events.clone(),
            exe_reads: Cell::new(0),
            stale_idle: None,
            bad_range: None,
            changed_generation: generation,
            changed_exe: exe,
            fail_at: None,
            panic_at: None,
        };
        let out = attribute_unselected_sharded(
            &sweep,
            &BTreeSet::new(),
            &BTreeSet::new(),
            &index(),
            &mut legacy(u64::MAX, u64::MAX)(),
            2,
            &make_io,
        );
        assert!(out.members.is_empty());
        assert_eq!(out.member_losses[&1001].0, want);
        let events = events.lock().unwrap();
        assert_eq!(events.requests, [(1001, 0x1000_1000, 0x1000_2000)]);
        assert!(events.pins.is_empty());
    }
}

fn d3a_policy_run(
    world: &BTreeMap<u32, Script>,
    policy: SegmentPolicy,
    threads: usize,
    work: u64,
    stale: Option<u32>,
    failure: Option<(u32, &'static str)>,
    panic: Option<(u32, &'static str)>,
) -> (
    SweepAttribution,
    State,
    std::sync::Arc<Mutex<D3aEvents>>,
    ReservationOwner,
) {
    let events = std::sync::Arc::new(Mutex::new(D3aEvents::default()));
    let make_io = || D3aIo {
        world,
        events: events.clone(),
        exe_reads: Cell::new(0),
        stale_idle: stale,
        bad_range: None,
        changed_generation: false,
        changed_exe: false,
        fail_at: failure,
        panic_at: panic,
    };
    let sweep: Vec<_> = world
        .iter()
        .map(|(&pid, script)| (pid, script.phase_one.clone()))
        .collect();
    let owner = ReservationOwner::new(policy);
    let mut budget = legacy(u64::MAX, work)();
    let out = attribute_unselected_with_policy(
        &sweep,
        &BTreeSet::new(),
        &BTreeSet::new(),
        &index(),
        &mut budget,
        policy,
        &owner,
        threads,
        &make_io,
    );
    (out, budget.confirm_state_for_test(), events, owner)
}

/// Catches borrowing the 64-FD reserve, multiplying caps per shard and
/// confusing an unavailable batch with an unavailable immediate operation.
#[test]
fn d3a_headroom_zero_one_and_multiple_workers() {
    let mut world = d3a_caller_world(&[1001, 1002, 1003]);
    world.get_mut(&1003).unwrap().phase_one = p11scope_manifest::maps::parse_maps(
        line(
            0x1000_0000,
            "r--p",
            PROVIDER,
            "/usr/lib/softhsm/libsofthsm2.so",
        )
        .as_bytes(),
    )
    .unwrap();
    for headroom in [0, 1, 2, 3, 4, 5, 6, 12, 64] {
        let policy = SegmentPolicy::from_headroom(headroom, 4, world.len());
        let (serial, state, events, owner) =
            d3a_policy_run(&world, policy, 1, u64::MAX, None, None, None);
        let events = events.lock().unwrap();
        assert!(events.pins.is_empty());
        assert_eq!(owner.state_for_test().0, [0; 4]);
        assert!(owner.state_for_test().2 <= headroom);
        assert!(owner.state_for_test().3 <= headroom);
        if headroom < 3 {
            assert!(events.events.is_empty());
            assert!(serial.members.is_empty());
            assert_eq!(
                serial.member_losses.keys().copied().collect::<Vec<_>>(),
                [1001, 1002]
            );
            assert!(serial.member_losses.values().all(|(loss, _)| *loss
                == crate::discovery::sweep_attribution::AttributionLoss::ConfirmUnreadable));
            assert_eq!(state.1, 0);
        } else {
            assert_eq!(
                serial
                    .members
                    .iter()
                    .map(|member| member.pid)
                    .collect::<Vec<_>>(),
                [1001, 1002]
            );
            assert_eq!(state.1, 2);
            assert!(events.peak_pins <= policy.retained.max(1));
            if headroom <= 6 {
                assert_eq!(events.peak_pins, 1);
            }
        }
        drop(events);
        let (parallel, parallel_state, _, owner) =
            d3a_policy_run(&world, policy, 4, u64::MAX, None, None, None);
        assert_eq!(parallel, serial, "H={headroom}");
        assert_eq!(parallel_state, state, "H={headroom}");
        assert_eq!(owner.state_for_test().0, [0; 4]);
    }
    let world = d3a_caller_world(&[1001, 1002, 1003, 1004, 1005, 1006, 1007, 1008]);
    let policy = SegmentPolicy::from_headroom(20, 4, world.len());
    let (_, _, events, owner) = d3a_policy_run(&world, policy, 4, u64::MAX, None, None, None);
    let events = events.lock().unwrap();
    assert!(
        events.proof_threads.len() > 1,
        "normal headroom lost A5 parallelism"
    );
    assert!(events.peak_pins <= policy.retained);
    assert!(events.pins.is_empty());
    assert_eq!(owner.state_for_test().0, [0; 4]);
    assert!(owner.state_for_test().1[0] <= policy.retained);
    assert!(owner.state_for_test().1[1] <= 2 * policy.workers);
}

#[test]
fn d3a_zero_headroom_preserves_settled_facts() {
    use crate::discovery::sweep_attribution::AttributionLoss;
    let mut world = d3a_caller_world(&[1001, 1002, 1003, 1004, 1005, 1006, 1007]);
    for (pid, text) in [
        (1003, line(0x3000_0000, "r-xp", 9001, "/usr/lib/unknown.so")),
        (
            1004,
            line(
                0x1000_0000,
                "r-xp",
                PROVIDER,
                "/usr/lib/softhsm/libsofthsm2.so (deleted)",
            ),
        ),
        (1005, object_lines(0x2000_0000, LIBC, "/usr/lib/libc.so.6")),
        (
            1007,
            line(
                0x1000_0000,
                "r--p",
                PROVIDER,
                "/usr/lib/softhsm/libsofthsm2.so",
            ),
        ),
    ] {
        world.get_mut(&pid).unwrap().phase_one =
            p11scope_manifest::maps::parse_maps(text.as_bytes()).unwrap();
    }
    let sweep: Vec<_> = world
        .iter()
        .map(|(&pid, script)| (pid, script.phase_one.clone()))
        .collect();
    let policy = SegmentPolicy::from_headroom(0, 4, world.len());
    let owner = ReservationOwner::new(policy);
    let mut budget = legacy(u64::MAX, u64::MAX)();
    let make_io = || -> D3aIo<'_> { panic!("zero headroom must never construct an I/O adapter") };
    let out = attribute_unselected_with_policy(
        &sweep,
        &BTreeSet::from([1002]),
        &BTreeSet::from([1001]),
        &index(),
        &mut budget,
        policy,
        &owner,
        4,
        &make_io,
    );
    assert!(out.members.is_empty());
    assert_eq!(out.unavailable, 1);
    assert_eq!(out.probed, 1);
    assert_eq!(
        out.member_losses.keys().copied().collect::<Vec<_>>(),
        [1004, 1006]
    );
    assert_eq!(out.member_losses[&1004].0, AttributionLoss::DeletedMapping);
    assert_eq!(
        out.member_losses[&1006].0,
        AttributionLoss::ConfirmUnreadable
    );
    assert_eq!(out.unexamined, BTreeMap::from([(1003, 1), (1005, 1)]));
    assert_eq!(
        out.unexamined_objects,
        BTreeSet::from([key(LIBC), key(9001)])
    );
    assert_eq!(budget.confirm_state_for_test().0.attempted_io_bytes, 0);
    assert_eq!(budget.confirm_state_for_test().1, 1);
    assert_eq!(owner.state_for_test().0, [0; 4]);
    assert_eq!(owner.state_for_test().2, 0);
}

/// Catches committing a quota-rejected preview or retaining its pin during
/// replacement. The capture pays one read per accepted PID despite rereads.
#[test]
fn d3a_segment_replay_preview_is_uncommitted() {
    let world = d3a_caller_world(&[1001, 1002]);
    let mut policy = SegmentPolicy::from_headroom(64, 4, world.len());
    policy.max_ranges = 1;
    let expected_io: u64 = world
        .values()
        .map(|script| script.confirm_maps.as_ref().unwrap().len() as u64)
        .sum();
    for threads in [1, 4] {
        let (out, state, events, owner) =
            d3a_policy_run(&world, policy, threads, u64::MAX, None, None, None);
        assert_eq!(
            out.members
                .iter()
                .map(|member| member.pid)
                .collect::<Vec<_>>(),
            [1001, 1002]
        );
        assert!(out.losses.is_empty());
        assert!(out.unexamined_objects.is_empty());
        assert_eq!(state.0.attempted_io_bytes, expected_io);
        assert_eq!(state.0.stop, None);
        assert!(!state.0.stop_reported);
        assert_eq!(state.1, 2);
        let events = events.lock().unwrap();
        assert_eq!(
            events.requests,
            [
                (1001, 0x1000_1000, 0x1000_2000),
                (1002, 0x1000_1000, 0x1000_2000)
            ]
        );
        assert_eq!(
            events
                .events
                .iter()
                .filter(|event| **event == (1002, "maps"))
                .count(),
            2
        );
        assert!(events.pins.is_empty());
        assert_eq!(owner.state_for_test().0, [0; 4]);
    }
}

#[test]
fn d3a_idle_candidates_fix_the_pid_prefix_and_boundary_promotions() {
    let mut world = d3a_caller_world(&[1001, 1002, 1003]);
    world.get_mut(&1001).unwrap().phase_one.clear();
    world.get_mut(&1002).unwrap().phase_one = p11scope_manifest::maps::parse_maps(
        object_lines(0x2000_0000, LIBC, "/usr/lib/libc.so.6").as_bytes(),
    )
    .unwrap();
    let policy = SegmentPolicy::from_headroom(7, 4, world.len()); // fixed prefix of two PIDs
    for threads in [1, 4] {
        let (out, state, events, owner) =
            d3a_policy_run(&world, policy, threads, 2, Some(1002), None, None);
        assert_eq!(
            out.members
                .iter()
                .map(|member| member.pid)
                .collect::<Vec<_>>(),
            [1002]
        );
        assert_eq!(
            out.member_losses[&1003].0,
            crate::discovery::sweep_attribution::AttributionLoss::Budget
        );
        assert!(out.unexamined_objects.is_empty());
        assert_eq!(state.1, 2);
        let events = events.lock().unwrap();
        let maps: Vec<_> = events
            .events
            .iter()
            .filter(|(_, event)| *event == "maps")
            .map(|(pid, _)| *pid)
            .collect();
        assert_eq!(maps, [1002, 1003]);
        assert_eq!(
            events.requests,
            [
                (1002, 0x2000_1000, 0x2000_2000),
                (1002, 0x1000_1000, 0x1000_2000)
            ]
        );
        assert!(events.pins.is_empty());
        assert_eq!(owner.state_for_test().0, [0; 4]);
    }
}

#[test]
fn d3a_oversized_pid_is_one_immediate_segment() {
    let mut world = d3a_caller_world(&[1001]);
    let text = world[&1001].confirm_maps.as_ref().unwrap().clone()
        + &line(
            0x1000_3000,
            "r-xp",
            PROVIDER,
            "/usr/lib/softhsm/libsofthsm2.so",
        );
    world.get_mut(&1001).unwrap().phase_one =
        p11scope_manifest::maps::parse_maps(text.as_bytes()).unwrap();
    world.get_mut(&1001).unwrap().confirm_maps = Some(text.clone());
    let mut policy = SegmentPolicy::from_headroom(64, 4, world.len());
    policy.max_ranges = 1;
    let (out, state, events, owner) = d3a_policy_run(&world, policy, 4, u64::MAX, None, None, None);
    assert_eq!(
        out.members
            .iter()
            .map(|member| member.pid)
            .collect::<Vec<_>>(),
        [1001]
    );
    assert_eq!(state.1, 2);
    assert_eq!(state.0.attempted_io_bytes, text.len() as u64);
    let events = events.lock().unwrap();
    assert_eq!(
        events.requests,
        [
            (1001, 0x1000_1000, 0x1000_2000),
            (1001, 0x1000_3000, 0x1000_4000)
        ]
    );
    assert_eq!(
        events
            .events
            .iter()
            .filter(|event| **event == (1001, "maps"))
            .count(),
        2
    );
    assert!(events.pins.is_empty());
    assert_eq!(owner.state_for_test().0, [0; 4]);
    assert_eq!(owner.state_for_test().1[2], 1); // immediate pin was actually used
}

#[test]
fn d3a_prepare_prove_finish_failures_release_every_handle() {
    use crate::discovery::sweep_attribution::AttributionLoss;
    let world = d3a_caller_world(&[1001]);
    for headroom in [3, 6, 64] {
        let policy = SegmentPolicy::from_headroom(headroom, 4, world.len());
        for (stage, loss) in [
            ("pin", AttributionLoss::ConfirmUnreadable),
            ("before", AttributionLoss::ConfirmUnreadable),
            ("maps", AttributionLoss::ConfirmUnreadable),
            ("proof", AttributionLoss::MapFilesUnavailable),
            ("after", AttributionLoss::ConfirmUnreadable),
            ("start", AttributionLoss::ConfirmUnreadable),
        ] {
            let (out, _, events, owner) =
                d3a_policy_run(&world, policy, 4, u64::MAX, None, Some((1001, stage)), None);
            assert!(out.members.is_empty(), "H={headroom} stage={stage}");
            assert_eq!(
                out.member_losses[&1001].0, loss,
                "H={headroom} stage={stage}"
            );
            assert!(events.lock().unwrap().pins.is_empty());
            assert_eq!(owner.state_for_test().0, [0; 4]);
        }
    }
}

#[test]
fn d3a_cancellation_joins_tail_and_stops_new_dispatch() {
    use crate::discovery::sweep_attribution::AttributionLoss;
    let world = d3a_caller_world(&[1001, 1002, 1003, 1004, 1005, 1006]);
    let policy = SegmentPolicy::from_headroom(9, 4, world.len()); // W=P=2
    for stage in ["maps", "proof"] {
        let (out, _, events, owner) =
            d3a_policy_run(&world, policy, 2, u64::MAX, None, None, Some((1001, stage)));
        assert!(out.members.is_empty());
        assert_eq!(
            out.member_losses.keys().copied().collect::<Vec<_>>(),
            [1001, 1002, 1003, 1004, 1005, 1006]
        );
        assert!(
            out.member_losses
                .values()
                .all(|(loss, _)| *loss == AttributionLoss::ConfirmUnreadable)
        );
        let events = events.lock().unwrap();
        assert!(events.pins.is_empty());
        assert!(!events.events.iter().any(|(pid, _)| *pid >= 1003));
        assert_eq!(owner.state_for_test().0, [0; 4]);
    }
}

/// Catches losing a failed spend's sticky/window/report mutation or replacing
/// capture state with the shadow, including refusal paths that look pure.
#[test]
fn d3a_shadow_journal_budget_equivalence() {
    for work in [0, 1, 2] {
        for reported in [false, true] {
            let mut budget = legacy(3, work)();
            if reported {
                let _ = budget.spend(work + 1);
                let _ = budget.take_scan_stop_reason();
            }
            let before = budget.confirm_state_for_test();
            let mut journal = BudgetJournal::new(&budget);
            let mut expected = budget.shard_shadow();
            for _ in 0..3 {
                assert_eq!(journal.spend(), expected.spend(1));
            }
            assert_eq!(
                journal.take_scan_stop_reason(),
                expected.take_scan_stop_reason()
            );
            let wanted = 8;
            let allowed = journal.allowed_capture_io(wanted);
            assert_eq!(
                allowed,
                MapsReadBudget::allowed_capture_io(&mut expected, wanted)
            );
            journal.record_io(allowed);
            expected.record_io(allowed);
            assert_eq!(
                journal.check_deadline(Some(T0)),
                expected.check_deadline(Some(T0))
            );
            assert_eq!(
                journal.take_scan_stop_reason(),
                expected.take_scan_stop_reason()
            );
            assert_eq!(
                budget.confirm_state_for_test(),
                before,
                "preview touched capture state"
            );
            journal.commit(&mut budget).unwrap();
            assert_eq!(
                budget.confirm_state_for_test(),
                expected.confirm_state_for_test()
            );
        }
    }
    for (io, work, deadline, now) in [
        (1, 1, u64::MAX, Some(T0)),
        (8, 1, T0, Some(T0)),
        (8, 1, T0 + 1, None),
    ] {
        let limits = InventoryDiscoveryLimits::new(
            1,
            InventoryWindowLimits::new(io, work, 64, 1 << 16, 64).unwrap(),
            InventoryRetainedLimits::new(16, 16, 16, 4, 4, 64 * 1024).unwrap(),
        )
        .unwrap();
        let mut budget = CaptureWorkBudget::for_inventory(limits);
        let token = budget.begin_window(WindowId::new(1), deadline).unwrap();
        budget.checkpoint(token).unwrap();
        let mut expected = budget.shard_shadow();
        let mut journal = BudgetJournal::new(&budget);
        assert_eq!(journal.check_deadline(now), expected.check_deadline(now));
        let allowed = journal.allowed_capture_io(8);
        assert_eq!(
            allowed,
            MapsReadBudget::allowed_capture_io(&mut expected, 8)
        );
        journal.record_io(allowed);
        expected.record_io(allowed);
        assert_eq!(
            journal.allowed_capture_io(8),
            MapsReadBudget::allowed_capture_io(&mut expected, 8)
        );
        for _ in 0..2 {
            assert_eq!(journal.spend(), expected.spend(1));
        }
        assert_eq!(
            journal.take_scan_stop_reason(),
            expected.take_scan_stop_reason()
        );
        journal.commit(&mut budget).unwrap();
        assert_eq!(
            budget.confirm_state_for_test(),
            expected.confirm_state_for_test()
        );
        assert_eq!(budget.window_exhaustions(), 1);
    }
    let mut budget = legacy(u64::MAX, 3)();
    let mut stale = BudgetJournal::new(&budget);
    stale.spend().unwrap();
    budget.spend(1).unwrap();
    assert_eq!(stale.commit(&mut budget), Err(DIVERGED));
    let mut budget = legacy(u64::MAX, 0)();
    assert!(budget.spend(1).is_err());
    let mut report = BudgetJournal::new(&budget);
    assert!(report.take_scan_stop_reason().is_some());
    assert!(budget.take_scan_stop_reason().is_some());
    assert_eq!(
        report.commit(&mut budget),
        Err(DIVERGED),
        "a consumed stop report must not be silently accepted"
    );
    let mut budget = legacy(u64::MAX, 0)();
    assert!(budget.spend(1).is_err());
    let empty = BudgetJournal::new(&budget);
    assert!(budget.take_scan_stop_reason().is_some());
    assert_eq!(
        empty.commit(&mut budget),
        Err(DIVERGED),
        "even an empty journal must reject report-only drift"
    );
}

/// Catches dropping only recorded answers while retaining a real speculative
/// pin, and charging physical rereads as additional accepted logical work.
#[test]
fn d3a_replay_mark_rejection_releases_before_reread() {
    let mut world = d3a_caller_world(&[1001, 1002, 1003, 1004]);
    let anon: String = (0..300u64)
        .map(|i| {
            let start = 0x5000_0000 + i * 0x2000;
            format!("{start:x}-{:x} rw-p 00000000 00:00 0 \n", start + 0x1000)
        })
        .collect();
    let first = world[&1001].confirm_maps.as_ref().unwrap().clone() + &anon;
    let heavy: String = (0..40u64)
        .map(|i| {
            line(
                0x1000_0000 + i * 0x2000,
                "r-xp",
                PROVIDER,
                "/usr/lib/softhsm/libsofthsm2.so",
            )
        })
        .collect();
    let idle = object_lines(0x2000_0000, LIBC, "/usr/lib/libc.so.6");
    for (pid, text) in [(1001, first.clone()), (1002, heavy), (1003, idle)] {
        world.get_mut(&pid).unwrap().phase_one =
            p11scope_manifest::maps::parse_maps(text.as_bytes()).unwrap();
        world.get_mut(&pid).unwrap().confirm_maps = Some(text);
    }
    let policy = SegmentPolicy::from_headroom(14, 2, world.len());
    let sweep: Vec<_> = world
        .iter()
        .map(|(&pid, script)| (pid, script.phase_one.clone()))
        .collect();
    let mut oracle = None;
    for threads in [1, 2] {
        let events = std::sync::Arc::new(Mutex::new(D3aEvents::default()));
        let make_io = || D3aIo {
            world: &world,
            events: events.clone(),
            exe_reads: Cell::new(0),
            stale_idle: None,
            bad_range: None,
            changed_generation: false,
            changed_exe: false,
            fail_at: None,
            panic_at: None,
        };
        let owner = ReservationOwner::new(policy);
        let ceiling = first.len() as u64 + 200;
        let mut budget = legacy(ceiling, 25)();
        let out = attribute_unselected_with_policy(
            &sweep,
            &BTreeSet::new(),
            &BTreeSet::new(),
            &index(),
            &mut budget,
            policy,
            &owner,
            threads,
            &make_io,
        );
        assert_eq!(
            out.members
                .iter()
                .map(|member| member.pid)
                .collect::<Vec<_>>(),
            [1001]
        );
        assert_eq!(
            out.member_losses.keys().copied().collect::<Vec<_>>(),
            [1002, 1004]
        );
        assert!(
            out.member_losses
                .values()
                .all(|(loss, _)| *loss
                    == crate::discovery::sweep_attribution::AttributionLoss::Budget)
        );
        assert!(out.unexamined_objects.is_empty());
        let state = budget.confirm_state_for_test();
        assert_eq!(state.0.attempted_io_bytes, ceiling);
        assert_eq!(state.0.stop, None); // detailed I/O refusal is non-sticky
        assert_eq!(state.1, 2);
        if let Some((expected, expected_state)) = &oracle {
            assert_eq!(&out, expected);
            assert_eq!(&state, expected_state);
        } else {
            oracle = Some((out.clone(), state));
        }
        let events = events.lock().unwrap();
        let opens = events
            .events
            .iter()
            .filter(|event| **event == (1004, "pin"))
            .count();
        assert_eq!(
            opens,
            if threads == 2 { 2 } else { 1 },
            "the cell must exercise uncovered replay"
        );
        assert!(events.pins.is_empty());
        assert!(events.peak_pins <= policy.retained);
        assert_eq!(owner.state_for_test().0, [0; 4]);
    }
}

/// Exercises the actual resource-aware one-PID helper used by phase D,
/// including unwind after pin acquisition, rather than its legacy wrapper.
#[test]
fn d3a_phase_d_helper_releases_immediate_resources() {
    use crate::discovery::sweep_attribution::AttributionLoss;
    let world = d3a_caller_world(&[1001]);
    let policy = SegmentPolicy::from_headroom(3, 4, world.len());
    for (stage, loss) in [
        ("pin", AttributionLoss::ConfirmUnreadable),
        ("before", AttributionLoss::ConfirmUnreadable),
        ("maps", AttributionLoss::ConfirmUnreadable),
        ("proof", AttributionLoss::MapFilesUnavailable),
        ("after", AttributionLoss::ConfirmUnreadable),
        ("start", AttributionLoss::ConfirmUnreadable),
    ] {
        let events = std::sync::Arc::new(Mutex::new(D3aEvents::default()));
        let owner = ReservationOwner::new(policy);
        let mut io = D3aIo {
            world: &world,
            events: events.clone(),
            exe_reads: Cell::new(0),
            stale_idle: None,
            bad_range: None,
            changed_generation: false,
            changed_exe: false,
            fail_at: Some((1001, stage)),
            panic_at: None,
        };
        let confirmation = confirm_with_resources(
            &mut io,
            1001,
            &index().map_files_keys(),
            &mut legacy(u64::MAX, u64::MAX)(),
            Some(&owner.immediate()),
        );
        match confirmation {
            Confirmation::Lost(actual, _) => assert_eq!(actual, loss, "{stage}"),
            Confirmation::Confirmed(read) if stage == "proof" => {
                assert_eq!(
                    read.mapped[&(0x1000_1000, 0x1000_2000)],
                    crate::discovery::sweep_attribution::RangeProof::Unavailable(
                        "scripted proof unavailable".into()
                    )
                );
            }
            other => panic!("{stage}: {other:?}"),
        }
        assert!(events.lock().unwrap().pins.is_empty());
        assert_eq!(owner.state_for_test().0, [0; 4]);
        assert!(owner.state_for_test().2 <= 3);
    }
    for stage in ["maps", "proof", "after"] {
        let events = std::sync::Arc::new(Mutex::new(D3aEvents::default()));
        let owner = ReservationOwner::new(policy);
        let mut io = D3aIo {
            world: &world,
            events: events.clone(),
            exe_reads: Cell::new(0),
            stale_idle: None,
            bad_range: None,
            changed_generation: false,
            changed_exe: false,
            fail_at: None,
            panic_at: Some((1001, stage)),
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            confirm_with_resources(
                &mut io,
                1001,
                &index().map_files_keys(),
                &mut legacy(u64::MAX, u64::MAX)(),
                Some(&owner.immediate()),
            )
        }));
        assert!(result.is_err());
        assert!(events.lock().unwrap().pins.is_empty());
        assert_eq!(owner.state_for_test().0, [0; 4]);
    }
}

#[test]
fn d3a_r1_one_worker_stays_on_caller() {
    let world = d3a_caller_world(&[1001, 1002, 1003]);
    let policy = SegmentPolicy::from_headroom(6, 4, world.len());
    let (out, state, events, owner) = d3a_policy_run(&world, policy, 4, u64::MAX, None, None, None);
    assert_eq!(
        out.members
            .iter()
            .map(|member| member.pid)
            .collect::<Vec<_>>(),
        [1001, 1002, 1003]
    );
    assert!(out.member_losses.is_empty());
    assert!(out.unexamined_objects.is_empty());
    assert_eq!(state.1, 3);
    let events = events.lock().unwrap();
    let caller = HashSet::from([std::thread::current().id()]);
    assert_eq!(
        events.prepare_threads, caller,
        "one-worker preparation must not spawn per PID"
    );
    assert_eq!(
        events.proof_threads, caller,
        "one-worker proof must stay on the caller"
    );
    assert!(events.pins.is_empty());
    assert_eq!(owner.state_for_test().0, [0; 4]);
    assert_eq!(owner.state_for_test().1[0], 1);
}

#[test]
fn d3a_r1_caller_queue_stops_after_later_record_panics() {
    let world = d3a_caller_world(&[1001, 1002, 1003, 1004, 1005, 1006]);
    let policy = SegmentPolicy::from_headroom(19, 4, world.len());
    assert_eq!((policy.workers, policy.retained), (4, 6));
    let owner = ReservationOwner::new(policy);
    let resources = owner.batch();
    let events = std::sync::Arc::new(Mutex::new(D3aEvents::default()));
    let make_io = || D3aIo {
        world: &world,
        events: events.clone(),
        exe_reads: Cell::new(0),
        stale_idle: None,
        bad_range: None,
        changed_generation: false,
        changed_exe: false,
        fail_at: None,
        panic_at: Some((1003, "maps")),
    };
    let sweep: Vec<_> = world
        .iter()
        .map(|(&pid, script)| (pid, script.phase_one.clone()))
        .collect();
    let index = index();
    let none = BTreeSet::new();
    let mut budget = legacy(u64::MAX, u64::MAX)();
    // With two executors and W=4, the caller owns positions0/2. Accepting
    // position0 queues position4; while waiting for the earlier worker's
    // reply, position2 panics. Position4 must never start after that panic.
    let (prepared, cancelled) = prepare_segment(
        &sweep,
        0..sweep.len(),
        &none,
        &none,
        &index,
        &index.map_files_keys(),
        &mut budget,
        policy,
        &resources,
        2,
        &make_io,
    );
    assert!(cancelled);
    assert_eq!(prepared.iter().map(|(at, _)| *at).collect::<Vec<_>>(), [0]);
    assert_eq!(budget.confirm_state_for_test().1, 1);
    assert_eq!(
        budget.confirm_state_for_test().0.attempted_io_bytes,
        world[&1001].confirm_maps.as_ref().unwrap().len() as u64
    );
    drop(prepared);
    let events = events.lock().unwrap();
    assert!(
        !events.events.iter().any(|(pid, _)| *pid >= 1005),
        "cancelled caller started another queued record"
    );
    assert!(events.requests.is_empty());
    assert!(events.pins.is_empty());
    assert_eq!(owner.state_for_test().0, [0; 4]);
    assert!(owner.state_for_test().1[0] <= policy.retained);
    assert!(owner.state_for_test().1[1] <= 2 * policy.workers);
    assert!(owner.state_for_test().2 <= policy.headroom);
}

/// Run each phase independently so pthread calls2/3 refuse respectively its
/// first/second worker. The reviewer injector is attached only to this test
/// process, never the compiler; normal runs remain preservation controls.
fn d3a_r1_spawn_refusal_phase(preparation: bool) {
    let world = d3a_caller_world(&[1001, 1002, 1003]);
    let policy = SegmentPolicy::from_headroom(12, 3, world.len());
    let owner = ReservationOwner::new(policy);
    let resources = owner.batch();
    let events = std::sync::Arc::new(Mutex::new(D3aEvents::default()));
    let make_io = || D3aIo {
        world: &world,
        events: events.clone(),
        exe_reads: Cell::new(0),
        stale_idle: None,
        bad_range: None,
        changed_generation: false,
        changed_exe: false,
        fail_at: None,
        panic_at: None,
    };
    let sweep: Vec<_> = world
        .iter()
        .map(|(&pid, script)| (pid, script.phase_one.clone()))
        .collect();
    let index = index();
    let prove = index.map_files_keys();
    let none = BTreeSet::new();
    let mut budget = legacy(u64::MAX, u64::MAX)();
    let prepared = if preparation {
        let (prepared, cancelled) = prepare_segment(
            &sweep,
            0..sweep.len(),
            &none,
            &none,
            &index,
            &prove,
            &mut budget,
            policy,
            &resources,
            3,
            &make_io,
        );
        assert!(!cancelled, "spawn refusal must not cancel attribution");
        prepared
    } else {
        sweep
            .iter()
            .enumerate()
            .map(|(at, (pid, entries))| {
                let recorded = record(
                    *pid,
                    entries,
                    &none,
                    &none,
                    &index,
                    &prove,
                    &mut budget.shard_shadow(),
                    &resources,
                    &make_io,
                );
                let (prepared, journal) = preview(recorded, *pid, &prove, &budget, &resources);
                journal.commit(&mut budget).unwrap();
                (at, prepared)
            })
            .collect()
    };
    assert_eq!(prepared.len(), 3);
    let proven = prove_segment(
        prepared,
        &sweep,
        &resources,
        if preparation { 1 } else { 3 },
    )
    .unwrap();
    let mut out = SweepAttribution::default();
    for (at, prepared) in proven {
        let PreparedState::Confirm { io, plan } = prepared.state else {
            panic!("caller preparation lost")
        };
        let confirmation = finish_confirmation(
            &io,
            sweep[at].0,
            plan,
            prepared.mapped,
            Some(&resources),
            &mut budget,
        );
        let mut probe = FinishedProbe {
            confirmation: Some(confirmation),
            mapped: MappedIdentities::new(),
        };
        attribute_one(
            &mut out,
            sweep[at].0,
            &sweep[at].1,
            &none,
            &none,
            &index,
            &prove,
            &mut probe,
            &mut budget,
        );
    }
    assert_eq!(
        out.members
            .iter()
            .map(|member| member.pid)
            .collect::<Vec<_>>(),
        [1001, 1002, 1003]
    );
    assert!(out.losses.is_empty());
    assert!(out.unexamined_objects.is_empty());
    assert_eq!(out.probed, 3);
    let state = budget.confirm_state_for_test();
    assert_eq!(state.1, 3);
    assert_eq!(
        state.0.attempted_io_bytes,
        world
            .values()
            .map(|script| script.confirm_maps.as_ref().unwrap().len() as u64)
            .sum::<u64>()
    );
    assert_eq!(state.0.stop, None);
    assert!(!state.0.stop_reported);
    let events = events.lock().unwrap();
    let mut requests = events.requests.clone();
    requests.sort_unstable();
    assert_eq!(
        requests,
        [
            (1001, 0x1000_1000, 0x1000_2000),
            (1002, 0x1000_1000, 0x1000_2000),
            (1003, 0x1000_1000, 0x1000_2000)
        ]
    );
    assert!(events.pins.is_empty());
    assert_eq!(events.peak_pins, 3);
    let threads = if preparation {
        &events.prepare_threads
    } else {
        &events.proof_threads
    };
    if let Ok(fail_at) = std::env::var("D3A_REVIEW_FAIL_PTHREAD_AT") {
        let expected = match fail_at.as_str() {
            "2" => 1,
            "3" => 2,
            _ => panic!("control requires refusal at first/second worker"),
        };
        assert_eq!(
            threads.len(),
            expected,
            "partial pool must be used with caller fallback"
        );
        assert!(threads.contains(&std::thread::current().id()));
    }
    assert_eq!(owner.state_for_test().0, [0; 4]);
    assert!(owner.state_for_test().1[0] <= policy.retained);
    assert!(owner.state_for_test().1[1] <= 2 * policy.workers);
    assert!(owner.state_for_test().2 <= policy.headroom);
}

#[test]
fn d3a_r1_prepare_spawn_refusal_keeps_segment() {
    d3a_r1_spawn_refusal_phase(true);
}

#[test]
fn d3a_r1_proof_spawn_refusal_keeps_segment() {
    d3a_r1_spawn_refusal_phase(false);
}
