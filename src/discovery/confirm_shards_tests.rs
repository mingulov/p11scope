//! SPDX-License-Identifier: GPL-3.0-or-later
//! C7 A5: the sharded confirmation is the serial one, attribution for
//! attribution and charge for charge, at every ceiling.

use super::*;
use crate::discovery::identity::{ExaminedObject, MappedFile, PinnedObjectId};
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

/// The serial path's probe over the same scripted `/proc`.
struct SerialProbe<'f, F> {
    make_io: &'f F,
}

impl<'w, F: Fn() -> FakeIo<'w>> MemberProbe for SerialProbe<'_, F> {
    fn confirm(
        &mut self,
        pid: u32,
        prove: &BTreeSet<ObjectKey>,
        budget: &mut CaptureWorkBudget,
    ) -> Confirmation {
        confirm_with(&mut (self.make_io)(), pid, prove, budget)
    }
    fn stat_ranges(
        &mut self,
        pid: u32,
        ranges: &[(u64, u64)],
        budget: &mut CaptureWorkBudget,
    ) -> MappedIdentities {
        stat_unpinned(&mut (self.make_io)(), pid, ranges, budget)
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
    let attribution = if shards <= 1 {
        attribute_unselected(
            &sweep,
            &unavailable,
            &selected,
            &index,
            &mut SerialProbe { make_io: &make_io },
            &mut budget,
        )
    } else {
        attribute_unselected_sharded(
            &sweep,
            &unavailable,
            &selected,
            &index,
            &mut budget,
            shards,
            &make_io,
        )
    };
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
