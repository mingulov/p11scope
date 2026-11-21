//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Run-tree first-map stop service (engine side). The kernel half
//! (`attach::member_stop`) stops a run member the first time it maps an
//! executable file this capture has not cleared, and leaves one pending
//! row per stopped member. Each tick this service takes the new rows,
//! looks at every executable file the stopped member maps, clears the
//! files that are not PKCS#11 providers (no later mapper stops on them),
//! and stages the providers through the learned-file path so their
//! probes attach before the member runs one instruction of them. The
//! member resumes as soon as its providers are attached, or after a
//! bounded hold. A hold that ends before the attach files the ordinary
//! first-use row, so a missed first run is never silent.
//!
//! Privacy: the service reads the member's maps rows (ranges, inode
//! identities, path spelling) and its `mountinfo` (keeping only FUSE and
//! overlay device numbers), and opens the mapped files read-only, like
//! the owned-tree watch scan. No memory, argument, environment or
//! payload is read.

use super::{Engine, EngineSession};
use p11scope_ebpf_common::{MemberFileKey, MemberStop};
use std::collections::{BTreeMap, BTreeSet};

/// The kernel half the service drives: the pending rows, the clearance
/// table, the counters and the end-of-capture switch. A trait so the
/// engine tests drive the service with real stopped processes and a
/// scripted table, without loading BPF.
pub(crate) trait MemberStopIo {
    /// Every pending stop: the member's tgid and the file whose first
    /// mapping stopped it.
    fn pending(&mut self) -> Result<Vec<(u32, MemberStop)>, String>;
    /// Marks a file cleared: later mappers of it never stop.
    fn clear(&mut self, file: MemberFileKey) -> Result<(), String>;
    /// Deletes one pending row (before the member resumes).
    fn withdraw(&mut self, tgid: u32) -> Result<(), String>;
    /// Requested, table-full, signal-refused, identity-unread totals.
    fn counters(&mut self) -> Result<[u64; 4], String>;
    /// Stops every new stop and detaches the hook; pending rows stay for
    /// the release. The detach does not wait for invocations already
    /// running (on 7.x every trampoline shares one ftrace ops, and beside
    /// another `uprobe_mmap` program it only swaps the trampoline image):
    /// [`Self::quiesce`] does.
    fn deactivate(&mut self) -> Result<(), String>;
    /// Waits, after [`Self::deactivate`], until every hook invocation that
    /// read `active` before it has finished (one RCU grace period: the
    /// hook runs inside an RCU read section), so a scan after it sees
    /// every row there will be. False when no such wait is proven (the
    /// map-in-map update is refused and `membarrier` gives none:
    /// `nohz_full`, one online CPU).
    fn quiesce(&mut self) -> bool;
    /// Whether the pinned process is in the run cgroup tree now. A row
    /// names only a tgid: its member may have exited and the number been
    /// reused by an unrelated process, which is never read or signalled.
    /// `Ok(false)` also when the pinned process exited meanwhile.
    fn is_run_member(&mut self, pin: &crate::process::PidPin) -> Result<bool, String>;
    /// Whether the watchdog that resumes members after an observer death
    /// is gone: then no member may stay stopped on this observer alone.
    fn guard_lost(&mut self) -> bool;
    /// [`Self::is_run_member`] for a process that cannot be pinned: the
    /// `/proc/<tgid>/cgroup` read alone.
    fn tgid_in_run_tree(&mut self, tgid: u32) -> Result<bool, String>;
}

/// The longest a member stays stopped for one provider attach, counted
/// from the kernel's stop. Past it the member resumes unprotected and the
/// first-use row is filed: a stuck attach never wedges the run
/// (never-stop). A member read late (a busy pass) resumes in the pass
/// that reads it.
pub(crate) const MEMBER_STOP_HOLD_NS: u64 = 1_000_000_000;
/// How long an unsettled release yields before its rescan, so a hook
/// call preempted on the observer's CPU can run.
pub(crate) const MEMBER_STOP_RESCAN_DELAY: std::time::Duration =
    std::time::Duration::from_millis(20);
/// Bounded memory of provider identities staged by a stop (the learned
/// settled set's own cap).
pub(crate) const MEMBER_STOP_STAGED_CAP: usize = 8192;
/// Stopped members taken per service pass, oldest stop first.
const MEMBER_STOP_INTAKE_PER_PASS: usize = 64;
/// Wall-time budget of one pass's intake (maps reads and ELF proofs).
const MEMBER_STOP_PASS_BUDGET: std::time::Duration = std::time::Duration::from_millis(100);
/// Wall-time budget of one member's maps read and proofs.
const MEMBER_STOP_MEMBER_BUDGET: std::time::Duration = std::time::Duration::from_millis(200);
/// Bounded maps read per stopped member.
const MEMBER_STOP_MAPS_BYTES: usize = 4 * 1024 * 1024;
/// Bounded files inspected per stopped member and service pass.
const MEMBER_STOP_FILES_PER_MEMBER: usize = 512;
/// Bounded refused-staging memory (the learned settled set's own cap).
const MEMBER_STOP_REFUSED_CAP: usize = 8192;
/// Bounded retry bookkeeping (the kernel table holds at most 1024 rows).
const MEMBER_STOP_RETRY_CAP: usize = 1024;
/// Bounded local clearance memory (the kernel LRU is the authority; this
/// only saves repeated proofs of files already cleared this capture).
const MEMBER_STOP_LOCAL_CLEARED_CAP: usize = 16_384;

/// Where a held member's hold stands (see `Engine::hold_state`).
struct HoldState {
    departed: bool,
    attached: bool,
    refused: bool,
}

/// One stopped member waiting for its providers' attach.
pub(crate) struct HeldMember {
    pin: crate::process::PidPin,
    /// Kernel identities to clear when the hold ends.
    files: Vec<MemberFileKey>,
    /// Pinned (`st_dev`, `st_ino`) identities of the providers staged
    /// for this member: the hold ends when all of them are attached.
    providers: Vec<(u64, u64)>,
    since_ns: u64,
    /// Whether the row's stop was single-threaded (for a forced resume
    /// after the row is out of reach).
    single_at_stop: bool,
    /// Whether the intake already counted this member departed (a corpse
    /// with staged providers): the hold's end must not count it again.
    departed_counted: bool,
}

/// Engine-side state of the first-map stop.
#[derive(Default)]
pub(crate) struct MemberStopState {
    pub(crate) held: BTreeMap<u32, HeldMember>,
    /// Kernel identities already cleared this capture.
    cleared: BTreeSet<MemberFileKey>,
    /// Pinned identities staged by a stop: their staging owes no
    /// first-use row while the stopped mapper still waits.
    pub(crate) stop_staged: BTreeSet<(u64, u64)>,
    /// Rows left in place for a retry (counted once as stopped), with
    /// the stop instant their bound runs from.
    retrying: BTreeMap<u32, u64>,
    /// The watchdog was lost: no further stops are made, and every pass
    /// only resumes whatever rows remain.
    disabled: bool,
    /// Pinned identities whose staging was refused (cap, replaced file,
    /// pin budget, nothing pinnable): settled, but never attached.
    refused: BTreeSet<(u64, u64)>,
    /// The release's grace-period wait was not proven: each member's maps
    /// are read before its resume, and the capture-end table is scanned
    /// again.
    unsettled: bool,
    /// Test override of [`MEMBER_STOP_INTAKE_PER_PASS`].
    #[cfg(test)]
    pub(crate) intake_cap: Option<usize>,
    /// Test override of [`MEMBER_STOP_PASS_BUDGET`].
    #[cfg(test)]
    pub(crate) pass_budget: Option<std::time::Duration>,
    /// Test override of [`MEMBER_STOP_MEMBER_BUDGET`].
    #[cfg(test)]
    pub(crate) member_budget: Option<std::time::Duration>,
    /// Tgids whose pin open fails (descriptor or `/proc` pressure), for
    /// the tests.
    #[cfg(test)]
    pub(crate) pin_fail: BTreeSet<u32>,
    /// Tgids whose maps read fails, for the tests.
    #[cfg(test)]
    pub(crate) maps_fail: BTreeSet<u32>,
    /// Devices (kernel encoding) the tests declare FUSE-backed.
    #[cfg(test)]
    pub(crate) fuse_devs: Option<BTreeSet<u64>>,
    /// Devices (kernel encoding) the tests declare overlay mounts.
    #[cfg(test)]
    pub(crate) overlay_devs: Option<BTreeSet<u64>>,
    pub(crate) stats: MemberStopStats,
}

impl MemberStopState {
    /// Records a provider identity staged by a stop, bounded: past the
    /// cap an identity is not retained and the overflow counts. Its
    /// staging then files the first-use row (one redundant row at worst,
    /// the safe direction).
    pub(crate) fn note_stop_staged(&mut self, identity: (u64, u64)) {
        if self.stop_staged.len() < MEMBER_STOP_STAGED_CAP || self.stop_staged.contains(&identity) {
            self.stop_staged.insert(identity);
        } else {
            self.stats.stop_staged_overflow = self.stats.stop_staged_overflow.saturating_add(1);
        }
    }

    /// Records a refused staging (bounded like the settled set: past the
    /// cap a refused identity is not retained, and its hold ends at the
    /// bound instead).
    pub(crate) fn note_refused(&mut self, identity: (u64, u64)) {
        if self.refused.len() < MEMBER_STOP_REFUSED_CAP {
            self.refused.insert(identity);
        }
    }
}

/// Service totals, for the diagnostic summary and the tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MemberStopStats {
    pub(crate) stopped: u64,
    pub(crate) cleared_files: u64,
    pub(crate) provider_holds: u64,
    pub(crate) attached_resumes: u64,
    pub(crate) timed_out: u64,
    /// Provider mappers resumed because their staging was refused.
    pub(crate) refused_resumes: u64,
    pub(crate) unreadable: u64,
    pub(crate) departed: u64,
    /// Stopped members kept for a retry: not pinnable, membership
    /// unverified, or no signal authority for the resume.
    pub(crate) resume_unavailable: u64,
    /// Rows whose tgid now names a process outside the run tree.
    pub(crate) not_members: u64,
    /// Members resumed at the bound without a pin or a verified
    /// membership (their files unproven): named first-use gap.
    pub(crate) forced_resumes: u64,
    /// Stopped members moved out of the run tree, resumed.
    pub(crate) moved_out_resumes: u64,
    /// Members resumed with their stopping file unproven (neither
    /// cleared nor staged): named first-use gap.
    pub(crate) unproven_resumes: u64,
    /// Held or pending members resumed unattached when the watchdog was
    /// lost: named first-use gap.
    pub(crate) lost_guard_resumes: u64,
    /// Stop-staged identities not retained past the cap (their staging
    /// then files the first-use row itself).
    pub(crate) stop_staged_overflow: u64,
    /// Members resumed unproven because a mapped file is FUSE-backed.
    pub(crate) fuse_resumes: u64,
    /// Release-time maps reads that waited out a member's in-flight hook
    /// invocation because no grace period was proven.
    pub(crate) unsettled_reads: u64,
}

/// One executable file row of a member's maps.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecRow {
    start: u64,
    end: u64,
    /// The identity cleared for this row: the `maps` one, or the kernel
    /// row's own for the stopping mapping.
    key: MemberFileKey,
    /// The inode number `maps` printed: what an opened file must match.
    maps_ino: u64,
    /// The device `maps` printed, in the kernel encoding.
    maps_dev: u64,
    /// The row the kernel stop names (its exact mapping).
    stopping: bool,
    path: Vec<u8>,
}

/// Each mount of a `mountinfo` listing: its filesystem type and its
/// device (kernel encoding). Parsed as bytes: a mount point is printed
/// raw apart from four escaped characters, so it need not be UTF-8.
/// Unparsable lines are skipped.
fn mount_types(mountinfo: &[u8]) -> impl Iterator<Item = (&[u8], u64)> {
    mountinfo.split(|byte| *byte == b'\n').filter_map(|line| {
        let separator = line.windows(3).position(|window| window == b" - ")?;
        let (mount, source) = (&line[..separator], &line[separator + 3..]);
        let fstype = source
            .split(|byte| *byte == b' ')
            .next()
            .unwrap_or_default();
        let device = mount.split(|byte| *byte == b' ').nth(2)?;
        let device = std::str::from_utf8(device).ok()?;
        let (major, minor) = device.split_once(':')?;
        Some((
            fstype,
            kernel_dev(major.parse::<u64>().ok()?, minor.parse::<u64>().ok()?),
        ))
    })
}

/// The devices (kernel encoding) of FUSE-backed mounts (`fuse`,
/// `fuse.*`, `fuseblk`, `fuseblk.*`) in a `mountinfo` listing.
fn fuse_devices(mountinfo: &[u8]) -> BTreeSet<u64> {
    mount_types(mountinfo)
        .filter(|(fstype, _)| {
            *fstype == b"fuse"
                || *fstype == b"fuseblk"
                || fstype.starts_with(b"fuse.")
                || fstype.starts_with(b"fuseblk.")
        })
        .map(|(_, device)| device)
        .collect()
}

/// The devices (kernel encoding) of overlay mounts in a `mountinfo`
/// listing.
fn overlay_devices(mountinfo: &[u8]) -> BTreeSet<u64> {
    mount_types(mountinfo)
        .filter(|(fstype, _)| *fstype == b"overlay")
        .map(|(_, device)| device)
        .collect()
}

/// Whether `tgid` is proven gone: its `/proc` directory does not exist.
/// Any other doubt keeps a stopped member's row.
pub(crate) fn process_gone(tgid: u32) -> bool {
    matches!(
        std::fs::symlink_metadata(format!("/proc/{tgid}")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
    )
}

/// Whether every task of `tgid` is dead (zombie `Z` or dead `X`/`x`):
/// nothing of the member can run code again.
///
/// The leader's `/proc` stat decides the common live case with one read;
/// only a dead leader pays the full task enumeration, because a dead
/// leader with live siblings still runs code. Any read or parse doubt
/// answers live (the intake then keeps today's gap behavior): silence is
/// only for proven death. An empty task set (reaped between the reads)
/// is dead: no task can run.
fn member_group_dead(tgid: u32) -> bool {
    fn is_dead(state: u8) -> bool {
        matches!(state, b'Z' | b'X' | b'x')
    }
    let leader = match std::fs::read(format!("/proc/{tgid}/stat")) {
        Ok(stat) => stat,
        Err(_) => return false,
    };
    match crate::discovery::pause::parse_task_state(&leader) {
        Some(state) if is_dead(state) => {}
        _ => return false,
    }
    let entries = match std::fs::read_dir(format!("/proc/{tgid}/task")) {
        Ok(entries) => entries,
        Err(_) => return false,
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => return false,
        };
        let stat = match std::fs::read(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(_) => return false,
        };
        match crate::discovery::pause::parse_task_state(&stat) {
            Some(state) if is_dead(state) => {}
            _ => return false,
        }
    }
    true
}

/// Whether `tgid` died with its row pending (reaped, or an unreaped
/// corpse whose every task is a zombie). Liveness only: whether the row
/// then withdraws silently is [`silent_corpse_withdrawal`]'s question.
fn member_died_with_row_pending(tgid: u32) -> bool {
    process_gone(tgid) || member_group_dead(tgid)
}

/// Whether a dead member's row withdraws silently (`None`), or keeps its
/// first-use gap (the cause to file).
///
/// Silence needs all three: the row's stop was single-threaded, the dead
/// occupant is the stopped generation, and the group is dead now (the
/// caller checked). A stopped single thread runs no userspace instruction
/// after its stopping mapping — the stop lands on its return-to-userspace
/// path — and it cannot clone while stopped, so nothing of that member
/// ran unobserved. Every other shape keeps the gap, the safe direction:
///
/// * a sibling thread of a multi-threaded member keeps running in
///   userspace until the group stop propagates to it (routine
///   millisecond-scale on a loaded host when the mapping thread blocks
///   in-kernel), and a mapping it makes while the row pends takes the
///   hook's EEXIST path: no signal, no count, no row. Withdrawing
///   without the maps snapshot would miss a provider it mapped and
///   called in that window, a real learned-file gap;
/// * a number reused since the stop names another process, whose own
///   mappings fell into the stale row's EEXIST shadow and ran
///   unprotected; only a start time that precedes the stop proves the
///   occupant is the stopped generation (the start is floored to a clock
///   tick, so a reuse within one tick of the stop is not told apart).
///
/// An unreadable thread count (zero), start time, stamp or clock is doubt
/// and keeps the gap. A refused kernel signal is still disclosed
/// separately through the refusal counters: only the intake's own gap is
/// ever silent.
fn silent_corpse_withdrawal(
    single_at_stop: bool,
    occupant_start: Option<u64>,
    stop_ns: u64,
) -> Option<&'static str> {
    if !single_at_stop {
        return Some("a sibling thread may have run after its stopping mapping");
    }
    if occupant_start.and_then(|start| born_before_stop(start, stop_ns)) != Some(true) {
        return Some("its process number may have been reused since its stop");
    }
    None
}

/// Sends `SIGCONT` to a process number (no pidfd could be opened).
fn signal_by_number(tgid: u32) -> std::io::Result<()> {
    let pid = i32::try_from(tgid).map_err(|_| std::io::Error::from_raw_os_error(libc::ESRCH))?;
    // SAFETY: `kill` takes a process number and a signal only.
    if unsafe { libc::kill(pid, libc::SIGCONT) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Whether a process that started at `start_ticks` (`/proc` starttime,
/// on the boot clock) already existed at the kernel stop stamped
/// `stop_ns` (on the monotonic clock): its age on the boot clock is at
/// least the stop's age on the monotonic clock. Ages need no conversion
/// between the two clocks; a suspend only makes the process look older.
/// The start is floored to a clock tick, so a number reused within one
/// tick of the stop is not told apart. A zero stamp or an unreadable
/// clock proves nothing: `None`, which callers treat as doubt (and
/// doubt resumes).
fn born_before_stop(start_ticks: u64, stop_ns: u64) -> Option<bool> {
    if stop_ns == 0 {
        return None;
    }
    let monotonic = crate::attach::monotonic_ns()?;
    let boot = crate::discovery::pause::boot_ns()?;
    let started = start_ticks.saturating_mul(crate::discovery::pause::clock_tick_ns());
    Some(boot.saturating_sub(started) >= monotonic.saturating_sub(stop_ns))
}

/// Whether a pinned process outside the run tree is still the member a
/// row stopped at `stop_ns`, moved out of the run cgroup while stopped:
/// its pinned start precedes the stop (or the stop instant proves
/// nothing: doubt resumes) and it is stopped now. Such a member is
/// resumed; any other process its number names is left as it is.
pub(crate) fn stopped_member_moved_out(pin: &crate::process::PidPin, stop_ns: u64) -> bool {
    pin.start_time()
        .is_some_and(|start| born_before_stop(start, stop_ns) != Some(false))
        && crate::attach::member_stop::process_stopped(pin.pid())
        && pin.still_the_same()
}

/// When a row's bound starts: the kernel's stamp (never later than this
/// pass), else the first pass that saw the row.
fn stop_since(stop: &MemberStop, first_seen: Option<u64>, now_ns: u64) -> u64 {
    match stop.hook_ts_ns {
        0 => first_seen.unwrap_or(now_ns),
        stamp => stamp.min(now_ns),
    }
}

/// Kernel `dev_t` encoding (`MKDEV`: major in the high 12 bits of 32).
fn kernel_dev(major: u64, minor: u64) -> u64 {
    (major << 20) | minor
}

/// Executable file rows of one maps snapshot: `x` permission, a nonzero
/// inode, a path. Malformed rows are skipped (the kernel never emits
/// them; a skip only means no clearance for that row).
fn exec_rows(maps: &[u8]) -> Vec<ExecRow> {
    let mut rows = Vec::new();
    for line in maps.split(|byte| *byte == b'\n') {
        let mut fields = line.splitn(6, |byte| *byte == b' ');
        let (Some(range), Some(perms), Some(_offset), Some(dev), Some(inode)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        let path = fields
            .next()
            .map(|rest| rest.trim_ascii_start())
            .unwrap_or_default();
        if perms.get(2) != Some(&b'x') || !path.starts_with(b"/") {
            continue;
        }
        let parse_hex = |text: &[u8]| {
            std::str::from_utf8(text)
                .ok()
                .and_then(|text| u64::from_str_radix(text, 16).ok())
        };
        let Some((start, end)) = std::str::from_utf8(range)
            .ok()
            .and_then(|range| range.split_once('-'))
            .and_then(|(start, end)| {
                Some((
                    u64::from_str_radix(start, 16).ok()?,
                    u64::from_str_radix(end, 16).ok()?,
                ))
            })
        else {
            continue;
        };
        let Some(colon) = dev.iter().position(|byte| *byte == b':') else {
            continue;
        };
        let (Some(major), Some(minor)) = (parse_hex(&dev[..colon]), parse_hex(&dev[colon + 1..]))
        else {
            continue;
        };
        let Some(ino) = std::str::from_utf8(inode)
            .ok()
            .and_then(|inode| inode.parse::<u64>().ok())
            .filter(|ino| *ino != 0)
        else {
            continue;
        };
        rows.push(ExecRow {
            start,
            end,
            key: MemberFileKey {
                dev: kernel_dev(major, minor),
                ino,
            },
            maps_ino: ino,
            maps_dev: kernel_dev(major, minor),
            stopping: false,
            path: path.to_vec(),
        });
    }
    rows
}

/// Puts the stopping file first under its kernel key. `maps` prints the
/// user-visible inode, while the hook reads the VMA's own file: for an
/// overlayfs (backing-file) mapping the device, and possibly the inode
/// number, differ from the row's. Only a row on an overlay mount (from
/// the member's `mountinfo`) may differ in both. The kernel row names its mapping's
/// exact range, so the `maps` row holding that range's start is the
/// stopping file whatever it prints; it is proven again under the kernel
/// key, so clearing that key is what stops later mappers from stopping on
/// the same file. Neighbor rows keep their `maps` keys (correct whenever
/// the two agree; a mismatched one costs one more stop for the first
/// mapper of that file, which then clears it under its own kernel key).
/// No row holds the range when it was unmapped since: nothing is added,
/// and the file stays uncleared. Only the exact mapping counts (the same
/// start and end), and in the kernel's own device domain the same inode
/// too: another thread of the member may replace the range before the
/// group stop completes, and the replacement proves nothing about the
/// stopped file, which then stays unproven (the named gap).
fn with_stopping_row(
    mut rows: Vec<ExecRow>,
    stop: &MemberStop,
    overlay: &BTreeSet<u64>,
) -> Vec<ExecRow> {
    let Some(at) = rows.iter().position(|row| {
        row.start == stop.vm_start
            && row.end == stop.vm_end
            && if row.maps_dev == stop.file.dev {
                row.maps_ino == stop.file.ino
            } else {
                overlay.contains(&row.maps_dev)
            }
    }) else {
        return rows;
    };
    if rows[at].key == stop.file {
        let mut row = rows.remove(at);
        row.stopping = true;
        rows.insert(0, row);
    } else {
        let row = ExecRow {
            key: stop.file,
            stopping: true,
            ..rows[at].clone()
        };
        rows.insert(0, row);
    }
    rows
}

/// Opens the file a maps row names. The `map_files` link follows the
/// VMA's own file and needs `CAP_CHECKPOINT_RESTORE` or `CAP_SYS_ADMIN`;
/// without either (or when that open fails) the row's path is opened
/// through the member's root. Either way the opened file must
/// still be the row's (see [`opened_row_file`]). A refusal only means the
/// row is not proven this pass.
fn open_exec_row(
    proc: &crate::process::ProcPin<'_>,
    pid: u32,
    row: &ExecRow,
    deadline: std::time::Instant,
) -> Result<std::fs::File, String> {
    use std::os::unix::ffi::OsStrExt as _;
    if let Ok(file) = proc.open_mapped_file(row.start, row.end, deadline) {
        return opened_row_file(file, row, true);
    }
    let path = row.path.strip_suffix(b" (deleted)").unwrap_or(&row.path);
    let mut rooted = std::ffi::OsString::from(format!("/proc/{pid}/root"));
    rooted.push(std::ffi::OsStr::from_bytes(path));
    let file =
        std::fs::File::open(&rooted).map_err(|error| format!("opening member file: {error}"))?;
    opened_row_file(file, row, false)
}

/// Accepts an opened file only when its inode number is the one the
/// maps snapshot printed. Another thread of the stopped member may remap
/// the range between the snapshot and the open, and a path may name a
/// newer file. Through `map_files` the kernel row's own inode number is
/// accepted too: on overlayfs that link opens the backing file, which
/// the hook keyed. The stopping row must open the kernel row's inode
/// itself (the VMA's own file is the stopped one); by path, also the
/// inode maps printed.
/// Inode numbers only: the device encodings differ between `stat` and
/// the kernel's superblock (btrfs subvolumes).
fn opened_row_file(
    file: std::fs::File,
    row: &ExecRow,
    through_map_files: bool,
) -> Result<std::fs::File, String> {
    use std::os::unix::fs::MetadataExt as _;
    let ino = file
        .metadata()
        .map_err(|error| format!("member file metadata: {error}"))?
        .ino();
    let accepted = if row.stopping {
        // By path, the file maps printed: the stopped one only when
        // that is the kernel row's inode too.
        ino == row.key.ino && (through_map_files || ino == row.maps_ino)
    } else {
        ino == row.maps_ino || (through_map_files && ino == row.key.ino)
    };
    if accepted {
        Ok(file)
    } else {
        Err("the opened member file is no longer the mapped inode".into())
    }
}

impl Engine {
    /// Whether any member is stopped by this capture right now.
    #[cfg(test)]
    pub(crate) fn member_stops_held(&self) -> bool {
        !self.member_stops.held.is_empty()
    }

    /// [`MEMBER_STOP_MEMBER_BUDGET`], or its test override.
    fn member_budget(&self) -> std::time::Duration {
        #[cfg(test)]
        if let Some(budget) = self.member_stops.member_budget {
            return budget;
        }
        MEMBER_STOP_MEMBER_BUDGET
    }

    #[cfg(test)]
    pub(crate) fn member_stop_stats_for_test(&self) -> MemberStopStats {
        self.member_stops.stats
    }

    #[cfg(test)]
    pub(crate) fn resume_member_for_test(
        io: &mut dyn MemberStopIo,
        pin: &crate::process::PidPin,
    ) -> bool {
        Self::resume_member(io, pin)
    }

    /// [`Self::resume_member`] with the signal send replaced.
    #[cfg(test)]
    pub(crate) fn resume_member_with_for_test(
        io: &mut dyn MemberStopIo,
        pin: &crate::process::PidPin,
        send: &mut dyn FnMut(&crate::process::PidPin) -> Result<(), String>,
    ) -> bool {
        Self::resume_member_with(io, pin, send)
    }

    /// The FUSE-backed and the overlay devices of a stopped member's
    /// mount namespace.
    fn member_mount_devices(
        &self,
        proc: &crate::process::ProcPin<'_>,
        deadline: std::time::Instant,
    ) -> Result<(BTreeSet<u64>, BTreeSet<u64>), String> {
        #[cfg(test)]
        if self.member_stops.fuse_devs.is_some() || self.member_stops.overlay_devs.is_some() {
            return Ok((
                self.member_stops.fuse_devs.clone().unwrap_or_default(),
                self.member_stops.overlay_devs.clone().unwrap_or_default(),
            ));
        }
        let mountinfo = proc.read_mountinfo(deadline, MEMBER_STOP_MAPS_BYTES)?;
        Ok((fuse_devices(&mountinfo), overlay_devices(&mountinfo)))
    }

    /// Pins a stopped member (tests can script the failure).
    fn open_member_pin(&self, tgid: u32) -> Result<crate::process::PidPin, String> {
        #[cfg(test)]
        if self.member_stops.pin_fail.contains(&tgid) {
            return Err(format!("scripted pin failure for {tgid}"));
        }
        crate::process::PidPin::open(tgid)
    }

    /// Holds `pin` as if a provider staging were pending since `since_ns`.
    #[cfg(test)]
    pub(crate) fn hold_member_for_test(
        &mut self,
        tgid: u32,
        pin: crate::process::PidPin,
        since_ns: u64,
    ) {
        self.member_stops.held.insert(
            tgid,
            HeldMember {
                pin,
                files: Vec::new(),
                providers: vec![(u64::MAX, u64::MAX)],
                since_ns,
                single_at_stop: true,
                departed_counted: false,
            },
        );
    }

    /// One service pass: takes new pending rows, proves their files,
    /// stages providers (and attaches them at once when the engine can),
    /// and resumes every member whose hold is done. Never fails the
    /// capture: every refusal resumes the member and counts.
    pub(crate) fn service_member_stops(
        &mut self,
        io: &mut dyn MemberStopIo,
        session: &mut dyn EngineSession,
        now_ns: Option<u64>,
    ) {
        if self.member_stops.disabled {
            self.drain_after_guard_loss(io, now_ns.or_else(crate::attach::monotonic_ns));
            return;
        }
        if io.guard_lost() {
            // Without the watchdog an observer death would leave members
            // stopped: stop stopping, and resume everyone now.
            self.member_stops.disabled = true;
            if crate::run::capture_diagnostics_on() {
                eprintln!("p11scope: member-stop watchdog gone; run member stops disabled");
            }
            self.release_after_guard_loss(
                io,
                &*session,
                now_ns.or_else(crate::attach::monotonic_ns),
            );
            return;
        }
        let Some(now_ns) = now_ns.or_else(crate::attach::monotonic_ns) else {
            return;
        };
        // Bounds first: a held member never waits on this pass's intake.
        self.resolve_member_holds(io, &*session, now_ns);
        // A failed table read skips only the intake: held members' bounds
        // are still enforced.
        let pending = match io.pending() {
            Ok(pending) => pending,
            Err(error) => {
                if crate::run::capture_diagnostics_on() {
                    eprintln!("p11scope: member stop table unreadable: {error}");
                }
                Vec::new()
            }
        };
        // Bounded intake, oldest stop first: the rest stay stopped with
        // their rows for the next pass (their bound runs from their own
        // stop), so a fork or loader burst never stalls the capture tick.
        let mut pending: Vec<_> = pending
            .into_iter()
            .filter(|(tgid, _)| !self.member_stops.held.contains_key(tgid))
            .collect();
        pending.sort_by_key(|(tgid, stop)| (stop.hook_ts_ns, *tgid));
        #[cfg(test)]
        let cap = self
            .member_stops
            .intake_cap
            .unwrap_or(MEMBER_STOP_INTAKE_PER_PASS);
        #[cfg(not(test))]
        let cap = MEMBER_STOP_INTAKE_PER_PASS;
        #[cfg(test)]
        let budget = self
            .member_stops
            .pass_budget
            .unwrap_or(MEMBER_STOP_PASS_BUDGET);
        #[cfg(not(test))]
        let budget = MEMBER_STOP_PASS_BUDGET;
        let pass_deadline = std::time::Instant::now() + budget;
        let mut staged = false;
        for (tgid, stop) in pending.into_iter().take(cap) {
            if std::time::Instant::now() >= pass_deadline {
                break;
            }
            staged |= self.intake_member_stop(io, tgid, stop, now_ns, pass_deadline);
        }
        if staged {
            self.service_learned_files();
        }
        // A held member waits on the attach: try it now rather than
        // after the rest of the tick (a no-op when nothing is staged).
        if !self.member_stops.held.is_empty() {
            self.apply_learned_staging(session);
        }
        self.resolve_member_holds(io, &*session, now_ns);
    }

    /// Takes one new stopped member. Returns whether it staged a
    /// provider (the hold then waits for the attach).
    fn intake_member_stop(
        &mut self,
        io: &mut dyn MemberStopIo,
        tgid: u32,
        stop: MemberStop,
        now_ns: u64,
        pass_deadline: std::time::Instant,
    ) -> bool {
        // A row kept for a retry counts once.
        let first_seen = self.member_stops.retrying.remove(&tgid);
        if first_seen.is_none() {
            self.member_stops.stats.stopped = self.member_stops.stats.stopped.saturating_add(1);
        }
        // The bound runs from the kernel's stop (the same monotonic clock).
        let since_ns = stop_since(&stop, first_seen, now_ns);
        let pin = match self.open_member_pin(tgid) {
            Ok(pin) => pin,
            Err(_) if process_gone(tgid) => {
                // Gone before its row was read: nothing is stopped.
                let _ = io.withdraw(tgid);
                self.member_stops.stats.departed =
                    self.member_stops.stats.departed.saturating_add(1);
                return false;
            }
            Err(error) => {
                // Alive but not pinnable now (descriptor or /proc
                // pressure): the row stays for a later pass, within the
                // bound.
                self.retry_or_force(io, tgid, since_ns, now_ns, &error, stop.nr_threads == 1);
                return false;
            }
        };
        if member_died_with_row_pending(tgid) {
            // Dead with its row still pending. Silence needs the
            // single-threaded stop of its own generation (a sibling may
            // have run after the stopping mapping, and a reused number
            // names another process); any doubt keeps the first-use gap.
            // Every withdrawn corpse is counted in `departed` (visible
            // on the `-v` stats line); never-admitted corpses are also
            // counted in their frames' descendant gaps.
            let doubt =
                silent_corpse_withdrawal(stop.nr_threads == 1, pin.start_time(), stop.hook_ts_ns);
            let _ = io.withdraw(tgid);
            let _ = pin.send_signal(libc::SIGCONT);
            self.member_stops.stats.departed = self.member_stops.stats.departed.saturating_add(1);
            if let Some(why) = doubt {
                self.note_first_use_gap(tgid, why);
            }
            return false;
        }
        match io.is_run_member(&pin) {
            Ok(true) => {}
            Ok(false) if stopped_member_moved_out(&pin, since_ns) => {
                // The stopped member itself, moved out of the run cgroup:
                // no longer this run's to hold, but never left stopped.
                // Its stopping file stays unproven and it may come back
                // into the tree, so the named first-use gap is filed (the
                // same row its forced twin files).
                if Self::resume_member(io, &pin) {
                    self.member_stops.stats.moved_out_resumes =
                        self.member_stops.stats.moved_out_resumes.saturating_add(1);
                    if crate::run::capture_diagnostics_on() {
                        eprintln!("p11scope: stopped member {tgid} left the run tree; resumed");
                    }
                    self.note_first_use_gap(tgid, "it left the run tree while stopped");
                } else {
                    self.retry_or_force(
                        io,
                        tgid,
                        since_ns,
                        now_ns,
                        "no signal authority",
                        stop.nr_threads == 1,
                    );
                }
                return false;
            }
            Ok(false) => {
                // Not a run member (any more): the stopped member is gone
                // and its number names another process, which is left
                // exactly as it is.
                let _ = io.withdraw(tgid);
                self.member_stops.stats.not_members =
                    self.member_stops.stats.not_members.saturating_add(1);
                return false;
            }
            Err(error) => {
                self.retry_or_force(
                    io,
                    tgid,
                    since_ns,
                    now_ns,
                    &format!("membership unverified: {error}"),
                    stop.nr_threads == 1,
                );
                return false;
            }
        }
        let deadline = (std::time::Instant::now() + self.member_budget()).min(pass_deadline);
        #[cfg(test)]
        let scripted_maps_failure = self.member_stops.maps_fail.contains(&tgid);
        #[cfg(not(test))]
        let scripted_maps_failure = false;
        let rows = pin
            .open_proc_dir()
            .and_then(|proc| {
                if scripted_maps_failure {
                    return Err("scripted maps failure".to_string());
                }
                let maps = proc.read_maps(deadline, MEMBER_STOP_MAPS_BYTES)?;
                let (fuse, overlay) = self.member_mount_devices(&proc, deadline)?;
                Ok((
                    proc,
                    with_stopping_row(exec_rows(&maps), &stop, &overlay),
                    fuse,
                ))
            })
            .map(|(proc, rows, fuse)| {
                // A FUSE-backed file is never opened: its server may be
                // another stopped member, and the open would block this
                // thread (and every bound) until it ran again.
                let (fuse_rows, rows): (Vec<_>, Vec<_>) = rows
                    .into_iter()
                    .partition(|row| fuse.contains(&row.maps_dev) || fuse.contains(&row.key.dev));
                (
                    self.prove_member_rows(&pin, &proc, rows, deadline),
                    fuse_rows,
                )
            });
        let ((cleared, providers), fuse_rows) = match rows {
            Ok(proven) => proven,
            Err(error) => {
                if member_died_with_row_pending(tgid) {
                    // Died between the intake check and this read: the
                    // same gated withdrawal as above, not an unreadable
                    // live member (a corpse counts departed, never
                    // unreadable).
                    let doubt = silent_corpse_withdrawal(
                        stop.nr_threads == 1,
                        pin.start_time(),
                        stop.hook_ts_ns,
                    );
                    let _ = io.withdraw(tgid);
                    let _ = pin.send_signal(libc::SIGCONT);
                    self.member_stops.stats.departed =
                        self.member_stops.stats.departed.saturating_add(1);
                    if let Some(why) = doubt {
                        self.note_first_use_gap(tgid, why);
                    }
                    return false;
                }
                self.member_stops.stats.unreadable =
                    self.member_stops.stats.unreadable.saturating_add(1);
                if crate::run::capture_diagnostics_on() {
                    eprintln!("p11scope: stopped run member {tgid} unreadable: {error}; resumed");
                }
                self.resume_or_force(io, &pin, since_ns, now_ns, stop.nr_threads == 1);
                // Nothing about its stopping file is proven: it may be a
                // provider whose first calls now run unwatched.
                self.note_first_use_gap(tgid, "its maps were unreadable");
                return false;
            }
        };
        for key in &cleared {
            self.clear_member_file(io, *key);
        }
        if !fuse_rows.is_empty() {
            // Unproven, so the named gap; cleared, so later mappers are
            // not stopped on them again (the owned-tree watch still
            // learns a FUSE-backed provider).
            for row in fuse_rows.iter().take(MEMBER_STOP_FILES_PER_MEMBER) {
                self.clear_member_file(io, row.key);
            }
            self.member_stops.stats.fuse_resumes =
                self.member_stops.stats.fuse_resumes.saturating_add(1);
            self.note_first_use_gap(tgid, "a mapped file is FUSE-backed");
        }
        // A stopping file that was not proven (unmapped since, or
        // unreadable) stays uncleared, so a later mapper stops and tries
        // again. This member runs with it unproven, whether at once or
        // after a hold for another provider it maps: it may be a
        // provider, so the named first-use gap is filed.
        let stopping_proven = cleared.contains(&stop.file)
            || self.member_stops.cleared.contains(&stop.file)
            || providers.iter().any(|(key, _)| *key == stop.file);
        // Whether this intake already counted the member departed: a hold
        // inserted below for such a corpse must not count it again when
        // the hold ends (in this pass's resolve, at a watchdog loss, or
        // at capture end).
        let mut departed_counted = false;
        if !stopping_proven {
            // A corpse counts departed; silence needs the
            // single-threaded stop of its own generation, and any doubt
            // keeps the first-use gap. Proving, staging and clearing
            // below still run on whatever the read snapshot carried (the
            // row still withdraws through the resume/hold path), so a
            // provider it mapped still attaches for later mappers.
            if member_died_with_row_pending(tgid) {
                self.member_stops.stats.departed =
                    self.member_stops.stats.departed.saturating_add(1);
                departed_counted = true;
                if let Some(why) = silent_corpse_withdrawal(
                    stop.nr_threads == 1,
                    pin.start_time(),
                    stop.hook_ts_ns,
                ) {
                    self.note_first_use_gap(tgid, why);
                }
            } else {
                self.member_stops.stats.unproven_resumes =
                    self.member_stops.stats.unproven_resumes.saturating_add(1);
                self.note_first_use_gap(tgid, "its stopping file was not proven");
            }
        }
        if providers.is_empty() {
            self.resume_or_force(io, &pin, since_ns, now_ns, stop.nr_threads == 1);
            return false;
        }
        let mut files = Vec::new();
        let mut identities = Vec::new();
        for (key, candidate) in providers {
            files.push(key);
            identities.push((candidate.dev, candidate.ino));
            let identity = (candidate.dev, candidate.ino);
            if self.learned_settled.contains(&identity)
                || self
                    .pending_learned
                    .iter()
                    .any(|queued| (queued.dev, queued.ino) == identity)
            {
                continue;
            }
            self.member_stops.note_stop_staged(identity);
            if self.pending_learned.len() >= crate::fanotify::LEARNED_FILES_PER_CAPTURE_CAP {
                self.refuse_learned_candidate(candidate);
            } else {
                self.pending_learned.push(candidate);
            }
        }
        if now_ns.saturating_sub(since_ns) >= MEMBER_STOP_HOLD_NS {
            // Read only after its bound: staged, but resumed at once, and
            // its first calls may run before the probes.
            for key in &files {
                self.clear_member_file(io, *key);
            }
            self.resume_or_force(io, &pin, since_ns, now_ns, stop.nr_threads == 1);
            self.note_unattached_resume(tgid);
            return true;
        }
        self.member_stops.stats.provider_holds =
            self.member_stops.stats.provider_holds.saturating_add(1);
        self.member_stops.held.insert(
            tgid,
            HeldMember {
                pin,
                files,
                providers: identities,
                since_ns,
                single_at_stop: stop.nr_threads == 1,
                departed_counted,
            },
        );
        true
    }

    /// A provider mapper resumed before its probes attached: counted, and
    /// the named first-use row is filed (its first calls may be missed).
    fn note_unattached_resume(&mut self, tgid: u32) {
        self.member_stops.stats.timed_out = self.member_stops.stats.timed_out.saturating_add(1);
        self.note_first_use_gap(tgid, "hold bound");
    }

    /// Files the named first-use row for a member resumed before any
    /// probe of a file it may use was attached (one deduped row per
    /// capture; over-reporting is the safe direction).
    fn note_first_use_gap(&mut self, tgid: u32, why: &str) {
        self.mark_partial(
            crate::render::LEARNED_SKIP_SUBJECT,
            crate::render::LEARNED_FIRST_RUN_REASON,
        );
        if crate::run::capture_diagnostics_on() {
            eprintln!("p11scope: run member {tgid} resumed before its provider attached ({why})");
        }
    }

    /// Proves every uncleared executable row: non-providers come back as
    /// keys to clear, providers as staged learned candidates.
    fn prove_member_rows(
        &self,
        pin: &crate::process::PidPin,
        proc: &crate::process::ProcPin<'_>,
        rows: Vec<ExecRow>,
        deadline: std::time::Instant,
    ) -> (
        Vec<MemberFileKey>,
        Vec<(MemberFileKey, crate::fanotify::LearnedCandidate)>,
    ) {
        let mut seen = BTreeSet::new();
        let mut cleared = Vec::new();
        let mut providers = Vec::new();
        for row in rows {
            if seen.len() >= MEMBER_STOP_FILES_PER_MEMBER {
                break;
            }
            if self.member_stops.cleared.contains(&row.key) || !seen.insert(row.key) {
                continue;
            }
            let Ok(file) = open_exec_row(proc, pin.pid(), &row, deadline) else {
                continue;
            };
            let naming = || match pin.pidfd() {
                Ok(fd) => crate::fanotify::loader_exe_for_pidfd(fd),
                Err(_) => (None, Some(crate::fanotify::LOADER_EXE_UNREADABLE_REASON)),
            };
            match crate::fanotify::prove_with_loader(&file, naming) {
                Ok(None) => cleared.push(row.key),
                // `--module` narrows discovery and `--exclude-module`
                // removes a provider: outside the selection a provider
                // is no provider for this capture, so it clears like a
                // non-provider (no staging, no hold, no first-use row).
                Ok(Some(_)) if self.outside_module_selection(&file, &row.path) => {
                    cleared.push(row.key);
                }
                Ok(Some((loader_exe, loader_unknown_reason))) => {
                    let Ok((dev, ino)) = file.metadata().map(|meta| {
                        use std::os::unix::fs::MetadataExt as _;
                        (meta.dev(), meta.ino())
                    }) else {
                        continue;
                    };
                    let display_path = crate::fanotify::display_path_for(&file)
                        .unwrap_or_else(|| String::from_utf8_lossy(&row.path).into_owned());
                    providers.push((
                        row.key,
                        crate::fanotify::LearnedCandidate {
                            file,
                            dev,
                            ino,
                            display_path,
                            loader_exe,
                            loader_unknown_reason,
                            run_learned: true,
                            proving_retained: false,
                        },
                    ));
                }
                // An I/O doubt is never cached: no clearance.
                Err(_) => {}
            }
        }
        (cleared, providers)
    }

    /// Whether a proven provider falls outside the capture's selection:
    /// with `--module` it must be one of the named files (the mapped
    /// path verbatim, or the same file identity as a hint, followed like
    /// the scan's hints), and no `--exclude-module` input may match it
    /// (identity, basename or soname, as in the scan).
    fn outside_module_selection(&self, file: &std::fs::File, mapped_path: &[u8]) -> bool {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::MetadataExt as _;
        let identity = file.metadata().ok().map(|meta| (meta.dev(), meta.ino()));
        let same_file = |input: &std::path::Path| {
            identity.is_some()
                && std::fs::metadata(input)
                    .ok()
                    .map(|meta| (meta.dev(), meta.ino()))
                    == identity
        };
        if !self.module_hints.is_empty()
            && !self
                .module_hints
                .iter()
                .any(|hint| hint.as_os_str().as_bytes() == mapped_path || same_file(hint))
        {
            return true;
        }
        let excludes = self.budget.excludes();
        if excludes.is_empty() {
            return false;
        }
        let is_path = |input: &std::path::PathBuf| input.as_os_str().as_bytes().contains(&b'/');
        let exclude_paths: crate::discovery::scan::ExcludePaths = excludes
            .iter()
            .filter(|input| is_path(input))
            .filter_map(|input| {
                std::fs::metadata(input)
                    .ok()
                    .map(|meta| (input.clone(), meta.dev(), meta.ino()))
            })
            .collect();
        let exclude_names: crate::discovery::scan::ExcludeNames = excludes
            .iter()
            .filter(|input| !is_path(input))
            .map(|input| (input.clone(), input.as_os_str().as_bytes().to_vec()))
            .collect();
        crate::discovery::scan::exclude_match(
            &String::from_utf8_lossy(mapped_path),
            file,
            &exclude_paths,
            &exclude_names,
        )
        .is_some()
    }

    fn clear_member_file(&mut self, io: &mut dyn MemberStopIo, key: MemberFileKey) {
        if io.clear(key).is_ok() {
            self.member_stops.stats.cleared_files =
                self.member_stops.stats.cleared_files.saturating_add(1);
            if self.member_stops.cleared.len() < MEMBER_STOP_LOCAL_CLEARED_CAP {
                self.member_stops.cleared.insert(key);
            }
        }
    }

    /// Resumes the member through its pidfd, then withdraws its row (so
    /// its next new file stops it again). The signal goes first: a send
    /// that fails while the member lives keeps the row, so a later pass,
    /// the bound, the final release and the watchdog still resume it. The
    /// hook refuses a second row for a tgid, so a file the member maps in
    /// the instant between the resume and the withdraw does not stop it.
    /// The owned-tree watch still learns such a file, and its staging
    /// files the first-use row, except when another member's stop already
    /// staged the same file (`stop_staged`): that narrow case (a second
    /// first mapper inside this microsecond window while the first is
    /// held) can miss the row. A pin without a pidfd is re-pinned and accepted only for the
    /// same start time. Returns false, with the row kept, when no resume
    /// was sent.
    fn resume_member(io: &mut dyn MemberStopIo, pin: &crate::process::PidPin) -> bool {
        Self::resume_member_with(io, pin, &mut |pin| pin.send_signal(libc::SIGCONT))
    }

    fn resume_member_with(
        io: &mut dyn MemberStopIo,
        pin: &crate::process::PidPin,
        send: &mut dyn FnMut(&crate::process::PidPin) -> Result<(), String>,
    ) -> bool {
        let fresh;
        let pin = if pin.probe_signal_authority().is_ok() {
            pin
        } else {
            match crate::process::PidPin::open(pin.pid()) {
                Ok(again)
                    if pin.start_time().is_some()
                        && again.start_time() == pin.start_time()
                        && again.probe_signal_authority().is_ok() =>
                {
                    fresh = again;
                    &fresh
                }
                _ => return false,
            }
        };
        // A failed send of an exited member leaves nothing stopped.
        if send(pin).is_err() && !matches!(pin.original_exited(), Ok(true)) {
            return false;
        }
        let _ = io.withdraw(pin.pid());
        true
    }

    /// [`Self::resume_member`], keeping the row for a retry on failure
    /// (the next pass's intake re-pins it, bounded).
    fn resume_or_retry(
        &mut self,
        io: &mut dyn MemberStopIo,
        pin: &crate::process::PidPin,
        since_ns: u64,
    ) {
        if !Self::resume_member(io, pin) {
            self.keep_for_retry(pin.pid(), since_ns, "no signal authority for the resume");
        }
    }

    /// [`Self::resume_member`] in an intake: a failure retries inside the
    /// bound and is forced at it.
    fn resume_or_force(
        &mut self,
        io: &mut dyn MemberStopIo,
        pin: &crate::process::PidPin,
        since_ns: u64,
        now_ns: u64,
        single_at_stop: bool,
    ) {
        if !Self::resume_member(io, pin) {
            self.retry_or_force(
                io,
                pin.pid(),
                since_ns,
                now_ns,
                "no signal authority for the resume",
                single_at_stop,
            );
        }
    }

    /// Keeps a row for a retry inside its bound; at the bound the member
    /// resumes anyway ([`Self::force_resume`]).
    fn retry_or_force(
        &mut self,
        io: &mut dyn MemberStopIo,
        tgid: u32,
        since_ns: u64,
        now_ns: u64,
        why: &str,
        single_at_stop: bool,
    ) {
        if now_ns.saturating_sub(since_ns) >= MEMBER_STOP_HOLD_NS {
            self.force_resume(io, tgid, since_ns, why, single_at_stop);
        } else {
            self.keep_for_retry(tgid, since_ns, why);
        }
    }

    /// Resumes a stopped member at its bound although it cannot be
    /// pinned, its membership cannot be read, or its pidfd refused the
    /// signal: the 1 s bound holds whatever `/proc` or the descriptor
    /// table do. The number is signalled only while it names the process
    /// the row stopped: its start time precedes the stop, or (start time
    /// unreadable too) the run-tree read does not place it outside;
    /// doubt resumes. A process proven born after the stop (a reused
    /// number) is never signalled. The member's files stay unproven and
    /// uncleared, so the named first-use gap row is filed. When a pin
    /// with signal authority can be opened now, the checks read the
    /// pinned process and the signal goes through its pidfd, so the
    /// number cannot be reused between the check and the signal; only
    /// without one is the number signalled. (`PidPin::open` reads the
    /// start time just before it opens the pidfd: a reuse inside those
    /// microseconds would need a full pid wrap, and is not told apart.)
    fn force_resume(
        &mut self,
        io: &mut dyn MemberStopIo,
        tgid: u32,
        stop_ns: u64,
        why: &str,
        single_at_stop: bool,
    ) {
        if process_gone(tgid) {
            let _ = io.withdraw(tgid);
            self.member_stops.stats.departed = self.member_stops.stats.departed.saturating_add(1);
            return;
        }
        if member_group_dead(tgid) {
            // Dead with its row still pending at the bound. Silence
            // needs the single-threaded stop of its own generation (the
            // start time is read fresh: no pin names the corpse here);
            // any doubt keeps the first-use gap. Either way nothing is
            // signalled: a number signal could resume a stranger reusing
            // the number.
            let doubt = silent_corpse_withdrawal(
                single_at_stop,
                crate::process::process_start_time(tgid).ok(),
                stop_ns,
            );
            let _ = io.withdraw(tgid);
            self.member_stops.stats.departed = self.member_stops.stats.departed.saturating_add(1);
            if let Some(why) = doubt {
                self.note_first_use_gap(tgid, why);
            }
            return;
        }
        let pin = self
            .open_member_pin(tgid)
            .ok()
            .filter(|pin| pin.probe_signal_authority().is_ok());
        let start = match pin.as_ref().and_then(crate::process::PidPin::start_time) {
            Some(start) => Ok(start),
            None => crate::process::process_start_time(tgid),
        };
        // A start time that proves nothing (no stop instant, no clock)
        // takes the same doubt branch as an unreadable one.
        let original = match start
            .ok()
            .and_then(|start| born_before_stop(start, stop_ns))
        {
            Some(original) => original,
            None => io.tgid_in_run_tree(tgid) != Ok(false),
        };
        if !original {
            let _ = io.withdraw(tgid);
            self.member_stops.stats.not_members =
                self.member_stops.stats.not_members.saturating_add(1);
            return;
        }
        if let Some(pin) = &pin {
            if let Err(error) = pin.send_signal(libc::SIGCONT) {
                if matches!(pin.original_exited(), Ok(true)) {
                    let _ = io.withdraw(tgid);
                    self.member_stops.stats.departed =
                        self.member_stops.stats.departed.saturating_add(1);
                } else {
                    self.keep_for_retry(tgid, stop_ns, &format!("forced resume refused: {error}"));
                }
                return;
            }
        } else if let Err(error) = signal_by_number(tgid) {
            if error.raw_os_error() == Some(libc::ESRCH) {
                let _ = io.withdraw(tgid);
                self.member_stops.stats.departed =
                    self.member_stops.stats.departed.saturating_add(1);
            } else {
                self.keep_for_retry(tgid, stop_ns, &format!("forced resume refused: {error}"));
            }
            return;
        }
        let _ = io.withdraw(tgid);
        self.member_stops.stats.forced_resumes =
            self.member_stops.stats.forced_resumes.saturating_add(1);
        self.mark_partial(
            crate::render::LEARNED_SKIP_SUBJECT,
            crate::render::LEARNED_FIRST_RUN_REASON,
        );
        if crate::run::capture_diagnostics_on() {
            eprintln!("p11scope: stopped run member {tgid} resumed at its bound ({why})");
        }
    }

    /// Leaves a stopped member's row in place for the next pass, counted.
    fn keep_for_retry(&mut self, tgid: u32, since_ns: u64, why: &str) {
        self.member_stops.stats.resume_unavailable =
            self.member_stops.stats.resume_unavailable.saturating_add(1);
        if self.member_stops.retrying.len() < MEMBER_STOP_RETRY_CAP {
            self.member_stops.retrying.insert(tgid, since_ns);
        }
        if crate::run::capture_diagnostics_on() {
            eprintln!("p11scope: stopped run member {tgid} kept for a retry: {why}");
        }
    }

    /// Where a hold stands: its member left, its providers are attached,
    /// or a staging was refused.
    fn hold_state(&self, held: &HeldMember, session: &dyn EngineSession) -> HoldState {
        // An unreadable exit state is not a departure: a departed member
        // is withdrawn without a resume, so doubt must resume.
        let departed = held.pin.original_exited().unwrap_or(false);
        // A refused staging settles without probes: never "attached".
        let refused = held
            .providers
            .iter()
            .any(|identity| self.member_stops.refused.contains(identity));
        // Attached means real session attach stamps, never scheduling
        // flags: a deferred, refused or no-link apply can clear those
        // without one probe live.
        let attached = !refused
            && held.providers.iter().all(|identity| {
                !self
                    .pending_learned
                    .iter()
                    .any(|queued| (queued.dev, queued.ino) == *identity)
                    && self.provider_object_attached(*identity, session)
            });
        HoldState {
            departed,
            attached,
            refused,
        }
    }

    /// Whether the provider file `identity` (its `(st_dev, st_ino)`) is
    /// attached: the plan holds at least one active slot on a pinned object
    /// of that file, and every such slot carries a real attach-complete
    /// stamp from the session (current, or its attach key's first) and is
    /// covered by a live session link (a stamp outlives a detach).
    fn provider_object_attached(&self, identity: (u64, u64), session: &dyn EngineSession) -> bool {
        use std::os::unix::fs::MetadataExt as _;
        let mut objects: BTreeMap<crate::discovery::identity::PinnedObjectId, bool> =
            BTreeMap::new();
        let mut any = false;
        for slot in self
            .plan
            .slots
            .iter()
            .filter(|slot| self.plan.is_active(slot.index))
        {
            let of_file = *objects.entry(slot.object).or_insert_with(|| {
                self.pinned
                    .file_for(slot.object)
                    .and_then(|file| file.metadata().ok())
                    .is_some_and(|meta| (meta.dev(), meta.ino()) == identity)
            });
            if !of_file {
                continue;
            }
            any = true;
            let stamped = session.slot_attached_at(slot.index).is_some()
                || session
                    .key_first_attach(crate::plan::AttachKey::of(slot))
                    .is_some();
            if !stamped || !session.has_slot_link(slot.index) {
                return false;
            }
        }
        any
    }

    /// The watchdog was lost: no new stops, and every held and pending
    /// member resumes now, accounted like a hold's end. A member resumed
    /// before its provider attached files the named first-use row (its
    /// staging, marked stop-staged, would otherwise stage silently). A
    /// member whose resume cannot be sent, or that cannot be pinned or
    /// verified, gets the start-time guarded forced resume at once: with
    /// no watchdog and no further stops, nothing else would bound it.
    fn release_after_guard_loss(
        &mut self,
        io: &mut dyn MemberStopIo,
        session: &dyn EngineSession,
        now_ns: Option<u64>,
    ) {
        self.end_kernel_stops(io);
        let held = std::mem::take(&mut self.member_stops.held);
        for (tgid, member) in held {
            let HoldState {
                departed,
                attached,
                refused,
            } = self.hold_state(&member, session);
            // As in `resolve_member_holds`: a departed hold clears its
            // providers only when attached; every other end files the row
            // (or is attached), so clearing is safe there.
            if !departed || attached {
                for key in &member.files {
                    self.clear_member_file(io, *key);
                }
            }
            if departed {
                let _ = io.withdraw(tgid);
                if !member.departed_counted {
                    self.member_stops.stats.departed =
                        self.member_stops.stats.departed.saturating_add(1);
                }
                continue;
            }
            if !Self::resume_member(io, &member.pin) {
                self.force_resume(
                    io,
                    tgid,
                    member.since_ns,
                    "watchdog lost",
                    member.single_at_stop,
                );
                continue;
            }
            if attached {
                self.member_stops.stats.attached_resumes =
                    self.member_stops.stats.attached_resumes.saturating_add(1);
            } else if refused {
                self.member_stops.stats.refused_resumes =
                    self.member_stops.stats.refused_resumes.saturating_add(1);
                self.note_first_use_gap(tgid, "its staging was refused");
            } else {
                self.member_stops.stats.lost_guard_resumes =
                    self.member_stops.stats.lost_guard_resumes.saturating_add(1);
                self.note_first_use_gap(tgid, "watchdog lost");
            }
        }
        if self.stop_staged_unattached(session) {
            // The hook is off from here on: no later mapper of a provider a
            // stop staged is stopped and held for its attach, and that
            // staging's own row is suppressed (`stop_staged`).
            self.mark_partial(
                crate::render::LEARNED_SKIP_SUBJECT,
                crate::render::LEARNED_FIRST_RUN_REASON,
            );
            if crate::run::capture_diagnostics_on() {
                eprintln!("p11scope: member-stop watchdog lost before a staged provider attached");
            }
        }
        self.drain_after_guard_loss(io, now_ns);
    }

    /// Whether a provider identity a stop staged may still be unattached:
    /// its staging is still queued, a staging is still unapplied, or the
    /// session holds no real attach stamp and link for its slots (doubt
    /// counts as unattached).
    fn stop_staged_unattached(&self, session: &dyn EngineSession) -> bool {
        let staged = &self.member_stops.stop_staged;
        !staged.is_empty()
            && (self.learned_unapplied
                || staged.iter().any(|identity| {
                    self.pending_learned
                        .iter()
                        .any(|queued| (queued.dev, queued.ino) == *identity)
                        || !self.provider_object_attached(*identity, session)
                }))
    }

    /// Resumes every pending row after the watchdog loss, on every pass:
    /// the hook is detached, so any row still present (an invocation that
    /// passed its active check before the detach, a refused forced
    /// resume, an unreadable table) is owed a resume, and no watchdog is
    /// left to give it.
    fn drain_after_guard_loss(&mut self, io: &mut dyn MemberStopIo, now_ns: Option<u64>) {
        let Ok(pending) = io.pending() else {
            // Unreadable: retried on the next pass.
            return;
        };
        let owed: BTreeMap<u32, u64> = std::mem::take(&mut self.member_stops.retrying);
        let now_ns = now_ns.unwrap_or(0);
        for (tgid, stop) in pending {
            let since_ns = stop_since(&stop, owed.get(&tgid).copied(), now_ns);
            self.resume_pending_after_guard_loss(io, tgid, since_ns, &stop);
        }
    }

    fn resume_pending_after_guard_loss(
        &mut self,
        io: &mut dyn MemberStopIo,
        tgid: u32,
        since_ns: u64,
        stop: &MemberStop,
    ) {
        let pin = match self.open_member_pin(tgid) {
            Ok(pin) => pin,
            Err(_) if process_gone(tgid) => {
                let _ = io.withdraw(tgid);
                self.member_stops.stats.departed =
                    self.member_stops.stats.departed.saturating_add(1);
                return;
            }
            Err(_) => {
                self.force_resume(
                    io,
                    tgid,
                    since_ns,
                    "watchdog lost; not pinnable",
                    stop.nr_threads == 1,
                );
                return;
            }
        };
        if member_died_with_row_pending(tgid) {
            // Dead with its row still pending when the guard was lost:
            // silence needs the single-threaded stop of its own
            // generation, and any doubt keeps the first-use gap. The
            // live members below keep their loud drain.
            let doubt =
                silent_corpse_withdrawal(stop.nr_threads == 1, pin.start_time(), stop.hook_ts_ns);
            let _ = io.withdraw(tgid);
            let _ = pin.send_signal(libc::SIGCONT);
            self.member_stops.stats.departed = self.member_stops.stats.departed.saturating_add(1);
            if let Some(why) = doubt {
                self.note_first_use_gap(tgid, why);
            }
            return;
        }
        let moved_out = match io.is_run_member(&pin) {
            Ok(true) => false,
            Ok(false) if stopped_member_moved_out(&pin, since_ns) => true,
            Ok(false) => {
                let _ = io.withdraw(tgid);
                self.member_stops.stats.not_members =
                    self.member_stops.stats.not_members.saturating_add(1);
                return;
            }
            Err(_) => {
                self.force_resume(
                    io,
                    tgid,
                    since_ns,
                    "watchdog lost; membership unverified",
                    stop.nr_threads == 1,
                );
                return;
            }
        };
        self.settle_member(&pin);
        if !Self::resume_member(io, &pin) {
            self.force_resume(
                io,
                tgid,
                since_ns,
                "watchdog lost; no signal authority",
                stop.nr_threads == 1,
            );
            return;
        }
        // Its stopping file was never proven: the named gap.
        if moved_out {
            self.member_stops.stats.moved_out_resumes =
                self.member_stops.stats.moved_out_resumes.saturating_add(1);
        } else {
            self.member_stops.stats.lost_guard_resumes =
                self.member_stops.stats.lost_guard_resumes.saturating_add(1);
        }
        self.note_first_use_gap(tgid, "watchdog lost");
    }

    /// Ends every hold whose providers are attached, whose member left,
    /// or whose bound passed.
    fn resolve_member_holds(
        &mut self,
        io: &mut dyn MemberStopIo,
        session: &dyn EngineSession,
        now_ns: u64,
    ) {
        let tgids: Vec<u32> = self.member_stops.held.keys().copied().collect();
        for tgid in tgids {
            let Some(held) = self.member_stops.held.get(&tgid) else {
                continue;
            };
            let HoldState {
                departed,
                attached,
                refused,
            } = self.hold_state(held, session);
            let expired = now_ns.saturating_sub(held.since_ns) >= MEMBER_STOP_HOLD_NS;
            if !(departed || attached || refused || expired) {
                continue;
            }
            let held = self.member_stops.held.remove(&tgid).expect("held member");
            if departed {
                // Its providers stay uncleared unless attached: the next
                // mapper of an unattached one is then stopped and held
                // (or files the row) instead of running it unprotected,
                // with the staging's row suppressed by `stop_staged`.
                if attached {
                    for key in &held.files {
                        self.clear_member_file(io, *key);
                    }
                }
                let _ = io.withdraw(tgid);
                // A corpse the intake already counted keeps its single
                // count: one departure, however the hold ends.
                if !held.departed_counted {
                    self.member_stops.stats.departed =
                        self.member_stops.stats.departed.saturating_add(1);
                }
                continue;
            }
            // Attached, refused or expired: a refused or expired end files
            // the row below, so the provider may be cleared.
            for key in &held.files {
                self.clear_member_file(io, *key);
            }
            self.resume_or_retry(io, &held.pin, held.since_ns);
            if attached {
                self.member_stops.stats.attached_resumes =
                    self.member_stops.stats.attached_resumes.saturating_add(1);
            } else if refused {
                // The refusal row names the provider; the first-use row
                // says its calls (from this member on) may be missed.
                self.member_stops.stats.refused_resumes =
                    self.member_stops.stats.refused_resumes.saturating_add(1);
                self.mark_partial(
                    crate::render::LEARNED_SKIP_SUBJECT,
                    crate::render::LEARNED_FIRST_RUN_REASON,
                );
            } else {
                // The member runs before its provider's probes: its first
                // calls may go unobserved, the same named first-use row a
                // learned file without a stop files.
                self.note_unattached_resume(tgid);
            }
        }
    }

    /// Stops the kernel refused (table full, signal refused, identity
    /// unread) let their members run unprotected, possibly a provider
    /// another member's stop staged without its row: one deduped
    /// first-use row discloses them (over-reporting is the safe
    /// direction). An unreadable counter is doubt, and files it too.
    fn note_kernel_stop_refusals(&mut self, io: &mut dyn MemberStopIo) {
        // Read after the grace-period wait: a refusal by an invocation in
        // flight at the deactivation counts.
        let refused = io.counters().map_or(1, |counts| {
            counts[1]
                .saturating_add(counts[2])
                .saturating_add(counts[3])
        });
        if refused > 0 {
            self.mark_partial(
                crate::render::LEARNED_SKIP_SUBJECT,
                crate::render::LEARNED_FIRST_RUN_REASON,
            );
        }
    }

    /// Ends the kernel half's stops before a release reads anything: no
    /// new stop, then the wait for hook invocations already running (the
    /// detach does not wait for them), then the refusal counters.
    fn end_kernel_stops(&mut self, io: &mut dyn MemberStopIo) {
        // A failed deactivation leaves `active` unproven: a call still
        // before its RCU read section is covered only by that write.
        let deactivated = io.deactivate().is_ok();
        self.member_stops.unsettled = !io.quiesce() || !deactivated;
        if self.member_stops.unsettled && crate::run::capture_diagnostics_on() {
            eprintln!(
                "p11scope: no grace period proven after the member-stop deactivation; \
                 each member's maps are read before its resume"
            );
        }
        self.note_kernel_stop_refusals(io);
    }

    /// Without a proven grace period, waits out a hook invocation still
    /// inside this member's mapping before its resume. The hook runs
    /// under the member's `mmap_lock`, held for writing by the mapping,
    /// and a maps read takes it: the read returns only after that
    /// invocation has inserted its row and sent its stop, so the resume
    /// that follows is the last signal. The deadline is checked between
    /// reads only: a read blocked on that lock (behind a fault the member
    /// cannot finish) waits with it. A failed read resumes without the
    /// wait.
    fn settle_member(&mut self, pin: &crate::process::PidPin) {
        if !self.member_stops.unsettled {
            return;
        }
        let deadline = std::time::Instant::now() + self.member_budget();
        let _ = pin
            .open_proc_dir()
            .and_then(|proc| proc.read_maps(deadline, MEMBER_STOP_MAPS_BYTES));
        self.member_stops.stats.unsettled_reads =
            self.member_stops.stats.unsettled_reads.saturating_add(1);
    }

    /// Capture end: no new stops, every held or pending member resumes.
    /// Pending rows the service never took resume too.
    pub(crate) fn release_member_stops(&mut self, io: &mut dyn MemberStopIo) {
        self.end_kernel_stops(io);
        // A resume that cannot be sent keeps its row: the hooks' own
        // release and the watchdog still resume that member. A held
        // member's stop completed before its intake read its maps.
        let held = std::mem::take(&mut self.member_stops.held);
        for (_, member) in held {
            // A held member that died waiting counts its departure like
            // the drain's; one the intake already counted keeps its
            // single count, and a live one is no departure.
            if !member.departed_counted && member.pin.original_exited().unwrap_or(false) {
                self.member_stops.stats.departed =
                    self.member_stops.stats.departed.saturating_add(1);
            }
            Self::resume_member(io, &member.pin);
        }
        self.resume_pending_at_release(io);
        if self.member_stops.unsettled {
            // A row inserted after that scan by an invocation the
            // unproven wait did not cover: on one CPU it runs only once
            // this thread blocks. The hooks' own release then ends the
            // watchdog by its sweep, which bounds a stop landing later.
            std::thread::sleep(MEMBER_STOP_RESCAN_DELAY);
            self.resume_pending_at_release(io);
        }
        if crate::run::capture_diagnostics_on() {
            let stats = self.member_stops.stats;
            let kernel = io.counters().unwrap_or_default();
            eprintln!(
                "p11scope: run member stops: {} stopped, {} files cleared, {} provider holds, \
                 {} resumed attached, {} resumed at bound, {} resumed refused, \
                 {} unreadable, {} departed, \
                 {} not members, {} kept for a retry, {} resumed unverified at bound, \
                 {} moved out and resumed, {} resumed unproven, \
                 {} resumed at watchdog loss, {} staged identities over the cap, \
                 {} resumed with a FUSE-backed file, {} settled by a maps read; \
                 kernel requested {}, table full {}, signal refused {}, identity unread {}",
                stats.stopped,
                stats.cleared_files,
                stats.provider_holds,
                stats.attached_resumes,
                stats.timed_out,
                stats.refused_resumes,
                stats.unreadable,
                stats.departed,
                stats.not_members,
                stats.resume_unavailable,
                stats.forced_resumes,
                stats.moved_out_resumes,
                stats.unproven_resumes,
                stats.lost_guard_resumes,
                stats.stop_staged_overflow,
                stats.fuse_resumes,
                stats.unsettled_reads,
                kernel[0],
                kernel[1],
                kernel[2],
                kernel[3],
            );
        }
    }

    /// Resumes every pending row at capture end (one table scan). After a
    /// lost watchdog nothing else bounds a stop, so every row goes through
    /// the loss drain: an unpinnable, unverified or unsignalable member
    /// gets the start-time guarded forced resume.
    fn resume_pending_at_release(&mut self, io: &mut dyn MemberStopIo) {
        if self.member_stops.disabled {
            self.drain_after_guard_loss(io, crate::attach::monotonic_ns());
            return;
        }
        for (tgid, stop) in io.pending().unwrap_or_default() {
            let Ok(pin) = crate::process::PidPin::open(tgid) else {
                // Gone: nothing is stopped, and a row left behind would
                // make the hooks' release hand a normal end to the
                // watchdog's sweep. The departure counts like the
                // drain's.
                if process_gone(tgid) {
                    let _ = io.withdraw(tgid);
                    self.member_stops.stats.departed =
                        self.member_stops.stats.departed.saturating_add(1);
                }
                continue;
            };
            match io.is_run_member(&pin) {
                Ok(true) => {
                    self.settle_member(&pin);
                    Self::resume_member(io, &pin);
                }
                Ok(false) if stopped_member_moved_out(&pin, stop.hook_ts_ns) => {
                    self.settle_member(&pin);
                    Self::resume_member(io, &pin);
                }
                Ok(false) => {
                    let _ = io.withdraw(tgid);
                }
                // Unreadable membership: the live watchdog's sweep bounds
                // the stop.
                Err(_) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The dead-group check: a live process is not dead, an unreaped
    /// zombie child is, and an unmapped pid answers live (doubt keeps
    /// the row and today's gap behavior).
    #[test]
    fn member_group_dead_pins_live_zombie_and_missing() {
        assert!(!member_group_dead(std::process::id()), "live self");
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id();
        let _ = child.kill();
        let mut zombie = false;
        for _ in 0..500 {
            if let Ok(stat) = std::fs::read(format!("/proc/{pid}/stat"))
                && crate::discovery::pause::parse_task_state(&stat) == Some(b'Z')
            {
                zombie = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        assert!(zombie, "the killed child never became a zombie");
        assert!(member_group_dead(pid), "an unreaped zombie is dead");
        let _ = child.wait();
        assert!(
            !member_group_dead(u32::MAX - 1),
            "an unmapped pid answers live"
        );
    }

    #[test]
    fn fuse_devices_come_from_mountinfo() {
        let mountinfo = b"22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw\n\
40 22 0:45 / /mnt/sq ro,nosuid shared:20 - fuse.squashfuse squashfuse ro,user_id=1000\n\
41 22 0:46 / /mnt/plain rw shared:21 - fuse /dev/fuse rw\n\
42 22 7:3 / /mnt/blk rw shared:22 - fuseblk /dev/loop3 rw\n\
43 22 0:47 / /mnt/fusectl rw shared:23 - fusectl fusectl rw\n";
        let devices = fuse_devices(mountinfo);
        assert_eq!(
            devices,
            BTreeSet::from([kernel_dev(0, 45), kernel_dev(0, 46), kernel_dev(7, 3)]),
            "fuse, fuse.* and fuseblk only"
        );
    }

    /// The kernel prints a FUSE block mount with its subtype too
    /// (`fuseblk.<subtype>`).
    #[test]
    fn fuseblk_subtypes_are_fuse_backed() {
        let mountinfo = b"44 22 7:4 / /mnt/exfat rw shared:24 - fuseblk.exfat /dev/loop4 rw\n\
45 22 7:5 / /mnt/fuseblkish rw shared:25 - fuseblkx /dev/loop5 rw\n";
        assert_eq!(
            fuse_devices(mountinfo),
            BTreeSet::from([kernel_dev(7, 4)]),
            "fuseblk.* only"
        );
    }

    /// `mountinfo` escapes only space, tab, newline and backslash: a
    /// mount point that is not UTF-8 is printed raw, and its FUSE mount
    /// must still be found.
    #[test]
    fn fuse_devices_parse_non_utf8_mount_paths() {
        let mut mountinfo = b"46 22 0:48 / /mnt/".to_vec();
        mountinfo.extend_from_slice(&[0xff, 0xfe]);
        mountinfo.extend_from_slice(b" rw shared:26 - fuse.sshfs host:/ rw\n");
        assert_eq!(
            fuse_devices(&mountinfo),
            BTreeSet::from([kernel_dev(0, 48)])
        );
    }

    #[test]
    fn overlay_devices_come_from_mountinfo() {
        let mountinfo = b"22 1 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw\n\
50 22 0:51 / /merged rw shared:30 - overlay overlay rw,lowerdir=/l,upperdir=/u,workdir=/w\n\
51 22 0:52 / /mnt/fo rw shared:31 - fuse.fuse-overlayfs fuse-overlayfs rw\n";
        assert_eq!(
            overlay_devices(mountinfo),
            BTreeSet::from([kernel_dev(0, 51)])
        );
    }

    /// A row at the stopping range on another device stands for the
    /// stopped file only when that device is an overlay mount (whose
    /// maps name the overlay inode while the hook keys the backing
    /// file); any other device there is a replaced mapping.
    #[test]
    fn a_stopping_row_on_another_device_needs_an_overlay_mount() {
        let row = ExecRow {
            start: 0x3000,
            end: 0x4000,
            key: MemberFileKey { dev: 43, ino: 7 },
            maps_ino: 7,
            maps_dev: 43,
            stopping: false,
            path: b"/usr/lib/libx.so".to_vec(),
        };
        let stop = MemberStop {
            file: MemberFileKey { dev: 23, ino: 7 },
            hook_ts_ns: 1,
            vm_start: 0x3000,
            vm_end: 0x4000,
            nr_threads: 1,
            reserved: 0,
        };
        let rows = with_stopping_row(vec![row.clone()], &stop, &BTreeSet::new());
        assert!(!rows.iter().any(|row| row.stopping), "not an overlay");
        let rows = with_stopping_row(vec![row], &stop, &BTreeSet::from([43]));
        assert!(rows[0].stopping, "an overlay mount");
    }

    /// Opened by path (no `map_files`), the stopping row proves the
    /// stopped file only when its maps inode is the kernel row's inode:
    /// the path names what maps printed, not the VMA's own file.
    #[test]
    fn a_path_opened_stopping_row_needs_the_stopped_inode() {
        use std::os::unix::fs::MetadataExt as _;
        let open = || std::fs::File::open("/proc/self/exe").unwrap();
        let ino = open().metadata().unwrap().ino();
        let row = ExecRow {
            start: 0x1000,
            end: 0x2000,
            key: MemberFileKey {
                dev: 1,
                ino: ino + 1,
            },
            maps_ino: ino,
            maps_dev: 2,
            stopping: true,
            path: b"/x".to_vec(),
        };
        assert!(opened_row_file(open(), &row, false).is_err());
        let same = ExecRow {
            key: MemberFileKey { dev: 1, ino },
            ..row
        };
        assert!(opened_row_file(open(), &same, false).is_ok());
    }

    /// The stopping row is the kernel's exact mapping: another range at
    /// the same start, or (same device domain) another inode there, is a
    /// replaced mapping and proves nothing about the stopped file.
    #[test]
    fn the_stopping_row_needs_the_exact_mapping_and_inode() {
        let row = |dev, ino, start, end| ExecRow {
            start,
            end,
            key: MemberFileKey { dev, ino },
            maps_ino: ino,
            maps_dev: dev,
            stopping: false,
            path: b"/usr/lib/libx.so".to_vec(),
        };
        let stop = |dev, ino, vm_start, vm_end| MemberStop {
            file: MemberFileKey { dev, ino },
            hook_ts_ns: 1,
            vm_start,
            vm_end,
            nr_threads: 1,
            reserved: 0,
        };
        let rows = with_stopping_row(
            vec![row(1, 7, 0x3000, 0x4000)],
            &stop(1, 7, 0x3000, 0x5000),
            &BTreeSet::new(),
        );
        assert!(!rows.iter().any(|row| row.stopping), "another range end");
        let rows = with_stopping_row(
            vec![row(1, 9, 0x3000, 0x4000)],
            &stop(1, 7, 0x3000, 0x4000),
            &BTreeSet::new(),
        );
        assert!(
            !rows.iter().any(|row| row.stopping),
            "another inode, same domain"
        );
        let rows = with_stopping_row(
            vec![row(1, 7, 0x3000, 0x4000)],
            &stop(1, 7, 0x3000, 0x4000),
            &BTreeSet::new(),
        );
        assert!(rows[0].stopping, "the exact mapping");
    }

    /// Through `map_files` the stopping row's file must be the kernel
    /// row's inode itself.
    #[test]
    fn a_stopping_row_opened_through_map_files_must_be_the_stopped_inode() {
        use std::os::unix::fs::MetadataExt as _;
        let open = || std::fs::File::open("/proc/self/exe").unwrap();
        let ino = open().metadata().unwrap().ino();
        let row = ExecRow {
            start: 0x1000,
            end: 0x2000,
            key: MemberFileKey {
                dev: 1,
                ino: ino + 1,
            },
            maps_ino: ino,
            maps_dev: 2,
            stopping: true,
            path: b"/x".to_vec(),
        };
        assert!(opened_row_file(open(), &row, true).is_err());
        let exact = ExecRow {
            key: MemberFileKey { dev: 1, ino },
            ..row
        };
        assert!(opened_row_file(open(), &exact, true).is_ok());
    }

    #[test]
    fn stop_staged_identities_are_bounded_and_the_overflow_counts() {
        let mut state = MemberStopState::default();
        for ino in 0..MEMBER_STOP_STAGED_CAP as u64 + 3 {
            state.note_stop_staged((7, ino));
        }
        assert_eq!(state.stop_staged.len(), MEMBER_STOP_STAGED_CAP);
        assert_eq!(state.stats.stop_staged_overflow, 3);
        // A retained identity stays retained.
        state.note_stop_staged((7, 0));
        assert_eq!(state.stats.stop_staged_overflow, 3);
    }

    #[test]
    fn the_stopping_row_is_proven_under_its_kernel_key() {
        let row = |dev, ino, start| ExecRow {
            start,
            end: start + 0x1000,
            key: MemberFileKey { dev, ino },
            maps_ino: ino,
            maps_dev: dev,
            stopping: false,
            path: b"/usr/lib/libx.so".to_vec(),
        };
        let stop = |dev, ino, vm_start| MemberStop {
            file: MemberFileKey { dev, ino },
            hook_ts_ns: 1,
            vm_start,
            vm_end: vm_start + 0x1000,
            nr_threads: 1,
            reserved: 0,
        };
        // Same domain: the exact row moves first, nothing is added.
        let rows = with_stopping_row(
            vec![row(1, 5, 0x1000), row(1, 7, 0x3000)],
            &stop(1, 7, 0x3000),
            &BTreeSet::new(),
        );
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].key, MemberFileKey { dev: 1, ino: 7 });
        // Overlay, other device: the row at the stopping range is proven
        // under the kernel key too.
        let rows = with_stopping_row(
            vec![row(43, 5, 0x1000), row(43, 7, 0x3000)],
            &stop(23, 7, 0x3000),
            &BTreeSet::from([43]),
        );
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].key, MemberFileKey { dev: 23, ino: 7 });
        assert_eq!(rows[0].start, 0x3000, "it reads the same mapping");
        // Overlay, other device and inode number: found by range alone.
        let rows = with_stopping_row(
            vec![row(43, 5, 0x1000), row(43, 7, 0x3000)],
            &stop(23, 991, 0x3000),
            &BTreeSet::from([43]),
        );
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].key, MemberFileKey { dev: 23, ino: 991 });
        assert_eq!(rows[0].start, 0x3000);
        assert_eq!(rows[0].maps_ino, 7, "an open still matches what maps names");
        // A same-inode row elsewhere is not the stopping mapping.
        let rows = with_stopping_row(
            vec![row(43, 7, 0x1000)],
            &stop(23, 7, 0x8000),
            &BTreeSet::from([43]),
        );
        assert_eq!(rows.len(), 1, "unmapped since: nothing to prove");
        assert_eq!(rows[0].key, MemberFileKey { dev: 43, ino: 7 });
    }

    /// A range remapped after the maps snapshot (or a path naming a newer
    /// file) opens another inode: refused, so nothing is proven, staged
    /// or cleared under the row's key.
    #[test]
    fn an_opened_file_must_be_the_mapped_inode() {
        use std::os::unix::fs::MetadataExt as _;
        let open = || std::fs::File::open("/proc/self/exe").unwrap();
        let ino = open().metadata().unwrap().ino();
        let row = |maps_ino, key_ino| ExecRow {
            start: 0x1000,
            end: 0x2000,
            key: MemberFileKey {
                dev: 1,
                ino: key_ino,
            },
            maps_ino,
            maps_dev: 1,
            stopping: false,
            path: b"/x".to_vec(),
        };
        assert!(opened_row_file(open(), &row(ino, ino), true).is_ok());
        assert!(opened_row_file(open(), &row(ino, ino), false).is_ok());
        assert!(opened_row_file(open(), &row(ino + 1, ino + 1), true).is_err());
        assert!(opened_row_file(open(), &row(ino + 1, ino + 1), false).is_err());
        // The kernel key's inode is the backing file's: map_files only.
        assert!(opened_row_file(open(), &row(ino + 1, ino), true).is_ok());
        assert!(opened_row_file(open(), &row(ino + 1, ino), false).is_err());
    }

    #[test]
    fn exec_rows_keep_only_executable_file_rows_with_kernel_dev() {
        let maps = b"5555-6666 r-xp 00001000 fd:01 1234   /usr/lib/libx.so\n\
7000-8000 r--p 00000000 fd:01 1234   /usr/lib/libx.so\n\
9000-a000 r-xp 00000000 00:00 0      [vdso]\n\
b000-c000 r-xp 00000000 00:2f 0      /memfd:jit (deleted)\n\
d000-e000 r-xp 00000000 103:05 77  /opt/with space.so\n";
        let rows = exec_rows(maps);
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert_eq!(
            rows[0].key,
            MemberFileKey {
                dev: (0xfd << 20) | 1,
                ino: 1234
            }
        );
        assert_eq!((rows[0].start, rows[0].end), (0x5555, 0x6666));
        assert_eq!(rows[0].path, b"/usr/lib/libx.so");
        assert_eq!(
            rows[1].key,
            MemberFileKey {
                dev: (0x103 << 20) | 5,
                ino: 77
            }
        );
        assert_eq!(rows[1].path, b"/opt/with space.so");
    }
}
