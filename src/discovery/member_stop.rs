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
//! identities, path spelling) and opens the mapped files read-only, like
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
    /// Stops every new stop; pending rows stay for the final release.
    fn deactivate(&mut self) -> Result<(), String>;
}

/// The longest a member stays stopped for one provider attach. Past it
/// the member resumes unprotected and the first-use row is filed: a
/// stuck attach never wedges the run (never-stop).
pub(crate) const MEMBER_STOP_HOLD_NS: u64 = 1_000_000_000;
/// Bounded maps read per stopped member.
const MEMBER_STOP_MAPS_BYTES: usize = 4 * 1024 * 1024;
/// Bounded files inspected per stopped member and service pass.
const MEMBER_STOP_FILES_PER_MEMBER: usize = 512;
/// Bounded local clearance memory (the kernel LRU is the authority; this
/// only saves repeated proofs of files already cleared this capture).
const MEMBER_STOP_LOCAL_CLEARED_CAP: usize = 16_384;

/// One stopped member waiting for its providers' attach.
pub(crate) struct HeldMember {
    pin: crate::process::PidPin,
    /// Kernel identities to clear when the hold ends.
    files: Vec<MemberFileKey>,
    /// Pinned (`st_dev`, `st_ino`) identities of the providers staged
    /// for this member: the hold ends when all of them are attached.
    providers: Vec<(u64, u64)>,
    since_ns: u64,
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
    pub(crate) stats: MemberStopStats,
}

/// Service totals, for the diagnostic summary and the tests.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MemberStopStats {
    pub(crate) stopped: u64,
    pub(crate) cleared_files: u64,
    pub(crate) provider_holds: u64,
    pub(crate) attached_resumes: u64,
    pub(crate) timed_out: u64,
    pub(crate) unreadable: u64,
    pub(crate) departed: u64,
}

/// One executable file row of a member's maps.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecRow {
    start: u64,
    end: u64,
    key: MemberFileKey,
    path: Vec<u8>,
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
            path: path.to_vec(),
        });
    }
    rows
}

/// Opens the file a maps row names. The `map_files` link is exact (the
/// kernel follows the VMA's own file) and needs `CAP_SYS_ADMIN`; without
/// it the row's path is opened through the member's root and accepted
/// only when its inode number matches the row. A refusal only means the
/// row is not proven this pass.
fn open_exec_row(
    proc: &crate::process::ProcPin<'_>,
    pid: u32,
    row: &ExecRow,
    deadline: std::time::Instant,
) -> Result<std::fs::File, String> {
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::MetadataExt as _;
    if let Ok(file) = proc.open_mapped_file(row.start, row.end, deadline) {
        return Ok(file);
    }
    let path = row.path.strip_suffix(b" (deleted)").unwrap_or(&row.path);
    let mut rooted = std::ffi::OsString::from(format!("/proc/{pid}/root"));
    rooted.push(std::ffi::OsStr::from_bytes(path));
    let file =
        std::fs::File::open(&rooted).map_err(|error| format!("opening member file: {error}"))?;
    let meta = file
        .metadata()
        .map_err(|error| format!("member file metadata: {error}"))?;
    if meta.ino() != row.key.ino {
        return Err("member file path no longer names the mapped inode".into());
    }
    Ok(file)
}

impl Engine {
    /// Whether any member is stopped by this capture right now.
    #[cfg(test)]
    pub(crate) fn member_stops_held(&self) -> bool {
        !self.member_stops.held.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn member_stop_stats_for_test(&self) -> MemberStopStats {
        self.member_stops.stats
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
        let Some(now_ns) = now_ns.or_else(crate::attach::monotonic_ns) else {
            return;
        };
        let pending = match io.pending() {
            Ok(pending) => pending,
            Err(error) => {
                if crate::run::capture_diagnostics_on() {
                    eprintln!("p11scope: member stop table unreadable: {error}");
                }
                return;
            }
        };
        let mut staged = false;
        for (tgid, stop) in pending {
            if self.member_stops.held.contains_key(&tgid) {
                continue;
            }
            staged |= self.intake_member_stop(io, tgid, stop, now_ns);
        }
        if staged {
            self.service_learned_files();
        }
        // A held member waits on the attach: try it now rather than
        // after the rest of the tick (a no-op when nothing is staged).
        if !self.member_stops.held.is_empty() {
            self.apply_learned_staging(session);
        }
        self.resolve_member_holds(io, now_ns);
    }

    /// Takes one new stopped member. Returns whether it staged a
    /// provider (the hold then waits for the attach).
    fn intake_member_stop(
        &mut self,
        io: &mut dyn MemberStopIo,
        tgid: u32,
        stop: MemberStop,
        now_ns: u64,
    ) -> bool {
        self.member_stops.stats.stopped = self.member_stops.stats.stopped.saturating_add(1);
        let Ok(pin) = crate::process::PidPin::open(tgid) else {
            // Gone before its row was read: nothing is stopped.
            let _ = io.withdraw(tgid);
            self.member_stops.stats.departed = self.member_stops.stats.departed.saturating_add(1);
            return false;
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(200);
        let rows = pin
            .open_proc_dir()
            .and_then(|proc| {
                let maps = proc.read_maps(deadline, MEMBER_STOP_MAPS_BYTES)?;
                Ok((proc, exec_rows(&maps)))
            })
            .map(|(proc, rows)| self.prove_member_rows(&pin, &proc, rows, deadline));
        let (cleared, providers) = match rows {
            Ok(proven) => proven,
            Err(error) => {
                self.member_stops.stats.unreadable =
                    self.member_stops.stats.unreadable.saturating_add(1);
                if crate::run::capture_diagnostics_on() {
                    eprintln!("p11scope: stopped run member {tgid} unreadable: {error}; resumed");
                }
                Self::resume_member(io, &pin);
                return false;
            }
        };
        for key in &cleared {
            self.clear_member_file(io, *key);
        }
        if providers.is_empty() {
            // The stopping file was not proven (unmapped since, or
            // unreadable): it stays uncleared, so a later mapper stops
            // and tries again.
            let _ = stop;
            Self::resume_member(io, &pin);
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
            self.member_stops.stop_staged.insert(identity);
            if self.pending_learned.len() >= crate::fanotify::LEARNED_FILES_PER_CAPTURE_CAP {
                self.refuse_learned_candidate(candidate);
            } else {
                self.pending_learned.push(candidate);
            }
        }
        self.member_stops.stats.provider_holds =
            self.member_stops.stats.provider_holds.saturating_add(1);
        self.member_stops.held.insert(
            tgid,
            HeldMember {
                pin,
                files,
                providers: identities,
                since_ns: now_ns,
            },
        );
        true
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

    fn clear_member_file(&mut self, io: &mut dyn MemberStopIo, key: MemberFileKey) {
        if io.clear(key).is_ok() {
            self.member_stops.stats.cleared_files =
                self.member_stops.stats.cleared_files.saturating_add(1);
            if self.member_stops.cleared.len() < MEMBER_STOP_LOCAL_CLEARED_CAP {
                self.member_stops.cleared.insert(key);
            }
        }
    }

    /// Withdraws the member's row, then resumes it through its pidfd.
    fn resume_member(io: &mut dyn MemberStopIo, pin: &crate::process::PidPin) {
        let _ = io.withdraw(pin.pid());
        let _ = pin.send_signal(libc::SIGCONT);
    }

    /// Ends every hold whose providers are attached, whose member left,
    /// or whose bound passed.
    fn resolve_member_holds(&mut self, io: &mut dyn MemberStopIo, now_ns: u64) {
        let tgids: Vec<u32> = self.member_stops.held.keys().copied().collect();
        for tgid in tgids {
            let Some(held) = self.member_stops.held.get(&tgid) else {
                continue;
            };
            let departed = held.pin.original_exited().unwrap_or(true);
            let attached = !self.learned_unapplied
                && held.providers.iter().all(|identity| {
                    self.learned_settled.contains(identity)
                        && !self
                            .pending_learned
                            .iter()
                            .any(|queued| (queued.dev, queued.ino) == *identity)
                });
            let expired = now_ns.saturating_sub(held.since_ns) >= MEMBER_STOP_HOLD_NS;
            if !(departed || attached || expired) {
                continue;
            }
            let held = self.member_stops.held.remove(&tgid).expect("held member");
            for key in &held.files {
                self.clear_member_file(io, *key);
            }
            if departed {
                let _ = io.withdraw(tgid);
                self.member_stops.stats.departed =
                    self.member_stops.stats.departed.saturating_add(1);
                continue;
            }
            Self::resume_member(io, &held.pin);
            if attached {
                self.member_stops.stats.attached_resumes =
                    self.member_stops.stats.attached_resumes.saturating_add(1);
            } else {
                // The member runs before its provider's probes: its first
                // calls may go unobserved, the same named first-use row a
                // learned file without a stop files.
                self.member_stops.stats.timed_out =
                    self.member_stops.stats.timed_out.saturating_add(1);
                self.mark_partial(
                    crate::render::LEARNED_SKIP_SUBJECT,
                    crate::render::LEARNED_FIRST_RUN_REASON,
                );
                if crate::run::capture_diagnostics_on() {
                    eprintln!(
                        "p11scope: run member {tgid} resumed before its provider attached (hold bound)"
                    );
                }
            }
        }
    }

    /// Capture end: no new stops, every held or pending member resumes.
    /// Pending rows the service never took resume too.
    pub(crate) fn release_member_stops(&mut self, io: &mut dyn MemberStopIo) {
        let _ = io.deactivate();
        let held = std::mem::take(&mut self.member_stops.held);
        for (_, member) in held {
            Self::resume_member(io, &member.pin);
        }
        for (tgid, _) in io.pending().unwrap_or_default() {
            if let Ok(pin) = crate::process::PidPin::open(tgid) {
                Self::resume_member(io, &pin);
            } else {
                let _ = io.withdraw(tgid);
            }
        }
        if crate::run::capture_diagnostics_on() {
            let stats = self.member_stops.stats;
            let kernel = io.counters().unwrap_or_default();
            eprintln!(
                "p11scope: run member stops: {} stopped, {} files cleared, {} provider holds, \
                 {} resumed attached, {} resumed at bound, {} unreadable, {} departed; \
                 kernel requested {}, table full {}, signal refused {}, identity unread {}",
                stats.stopped,
                stats.cleared_files,
                stats.provider_holds,
                stats.attached_resumes,
                stats.timed_out,
                stats.unreadable,
                stats.departed,
                kernel[0],
                kernel[1],
                kernel[2],
                kernel[3],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
