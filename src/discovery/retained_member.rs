//! SPDX-License-Identifier: GPL-3.0-or-later
//! Borrow-only custody on one live thread-group member (Z2).
//!
//! The original `Arc<PidPin>` stays authoritative: a `RetainedGroupMember`
//! only borrows it (a `Weak`), pins one `/proc/<tgid>/task/<tid>` directory,
//! and re-proves the member birth plus the leader birth on every use, so a
//! zombie leader's live survivor stays provable while exits, execs, TID
//! reuse and foreign groups all refuse. Task 3 routes the sweep confirm path
//! and the TID member runs through the selector and the relative reads.
//!
//! Failure policy: every refusal is fail-closed (`Err`/`None`), FDs close
//! before their leases return, and leases are reserved before any FD opens,
//! so a refusal path never opens anything. Unused-API note: `try_clone` and
//! `process_is_zombie` are deliberately not consumed — a dup'd pidfd cannot
//! gate minting, and the member zombie check rides the same single stat read
//! as the birth bracket (atomic where two reads would race).

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::Instant;

use crate::discovery::caller_registry::ExeIdentity;
use crate::discovery::identity::FileIdentity;
use crate::discovery::scan::CaptureWorkBudget;
use crate::discovery::sweep_attribution::{FdLease, RANGE_NOT_MAPPED, ReservationOwner};
use crate::process::{PidPin, generation_gone, process_start_time};

/// The discovery work units one mint charges (liveness, two stats, one status).
const MINT_WORK_UNITS: u64 = 4;

/// One live mint per (tgid, tid) slot. The minter Arc stays authoritative
/// while its member handle lives; any second mint for the slot refuses.
/// Entries are removed only by `Drop`, which always runs for a member.
struct MintRecord {
    minter: Weak<PidPin>,
}

static LIVE_MINTS: LazyLock<Mutex<HashMap<(u32, u32), MintRecord>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// A borrow-only handle on one live thread-group member: the held
/// `/proc/<tgid>/task/<tid>` directory plus the births that re-prove it.
/// The original `Arc<PidPin>` is only borrowed — never cloned, never
/// reopened by number — so it stays the sole authority.
pub(crate) struct RetainedGroupMember {
    /// Held member directory: the pin. Declared before the lease so it
    /// closes before its reservation returns (cf. `ReservedPin`).
    member_dir: OwnedFd,
    _retained: FdLease,
    fd_owner: ReservationOwner,
    original: Weak<PidPin>,
    tgid: u32,
    tid: u32,
    member_birth: u64,
    leader_birth: u64,
}

impl std::fmt::Debug for RetainedGroupMember {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedGroupMember")
            .field("tgid", &self.tgid)
            .field("tid", &self.tid)
            .field("member_birth", &self.member_birth)
            .field("leader_birth", &self.leader_birth)
            .finish_non_exhaustive()
    }
}

impl Drop for RetainedGroupMember {
    fn drop(&mut self) {
        debug_assert!(
            LIVE_MINTS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(&(self.tgid, self.tid))
                .is_some_and(|record| record.minter.as_ptr() == self.original.as_ptr()),
            "a live member always owns its registry slot"
        );
        LIVE_MINTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&(self.tgid, self.tid));
    }
}

/// A validated member selected for a TID proof run. Borrow-only: it cannot
/// outlive the member, and there is no numeric-TID constructor.
#[derive(Debug)]
pub(crate) struct ValidatedMemberSelector<'a> {
    member: &'a RetainedGroupMember,
}

impl ValidatedMemberSelector<'_> {
    pub(crate) fn tgid(&self) -> u32 {
        self.member.tgid
    }

    pub(crate) fn tid(&self) -> u32 {
        self.member.tid
    }

    pub(crate) fn member_birth(&self) -> u64 {
        self.member.member_birth
    }
}

/// A transiently held TID-addressed `map_files` directory with its own lease.
/// Declared directory-first so it closes before its reservation returns.
pub(crate) struct TransientMapFilesDir {
    dir: OwnedFd,
    _lease: FdLease,
}

impl TransientMapFilesDir {
    pub(crate) fn stat(&self, start: u64, end: u64) -> Result<FileIdentity, String> {
        let name = CString::new(format!("{start:x}-{end:x}")).map_err(|error| error.to_string())?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: a valid directory fd, a writable stat buffer read only on
        // success, and a NUL-terminated relative range name.
        if unsafe { libc::fstatat(self.dir.as_raw_fd(), name.as_ptr(), stat.as_mut_ptr(), 0) } != 0
        {
            let error = std::io::Error::last_os_error();
            // A renamed-away entry is the same "not mapped" verdict the
            // shared map_files reader reports, so member stats stay a
            // drop-in for `HeldMapFiles::stat` under `RangeProof::from`.
            if error.raw_os_error() == Some(libc::ENOENT) {
                return Err(RANGE_NOT_MAPPED.to_string());
            }
            return Err(error.to_string());
        }
        // SAFETY: initialized by the successful `fstatat`.
        let stat = unsafe { stat.assume_init() };
        Ok(FileIdentity {
            dev: stat.st_dev,
            ino: stat.st_ino,
        })
    }
}

impl RetainedGroupMember {
    /// Mint a handle on `tid_hint` as a live member of the original's group.
    /// Cost: 1 retained FD plus at most 2 transient, reserved before opening.
    pub(crate) fn acquire(
        original: &Arc<PidPin>,
        tid_hint: u32,
        fd_owner: &ReservationOwner,
        work: &mut CaptureWorkBudget,
        deadline: Instant,
    ) -> Result<Self, String> {
        Self::acquire_with_proc_opener(original, tid_hint, fd_owner, work, deadline, &open_proc_dir)
    }

    /// `acquire` with the `/proc` directory opener injected. Production
    /// passes the real opener; tests inject failures and races so permission
    /// failures and check/open races are deterministic.
    pub(crate) fn acquire_with_proc_opener(
        original: &Arc<PidPin>,
        tid_hint: u32,
        fd_owner: &ReservationOwner,
        work: &mut CaptureWorkBudget,
        deadline: Instant,
        open_proc: &dyn Fn(&Path) -> Result<OwnedFd, String>,
    ) -> Result<Self, String> {
        if Instant::now() >= deadline {
            return Err("retained member mint: deadline exhausted".to_string());
        }
        work.spend(MINT_WORK_UNITS)
            .map_err(|reason| reason.to_string())?;
        original
            .pidfd()
            .map_err(|_| "retained member mint requires the original pidfd".to_string())?;
        let resources = fd_owner.batch();
        let retained = resources.pin()?;
        let transient = resources.transient()?;
        let tgid = original.pid();
        if generation_gone(tgid) || !original.still_the_same() {
            return Err("original process exited before member mint".to_string());
        }
        let leader_live = process_start_time(tgid)
            .map_err(|_| "original process exited before member mint".to_string())?;
        if original.start_time() != Some(leader_live) {
            return Err(
                "process generation changed before member mint (pid reuse or exec)".to_string(),
            );
        }
        // Authoritative liveness + group anchor: tgkill(2) (pid-namespace
        // lookup). No task listing here: getdents skips entries under
        // concurrent modification and shows reaped tids as ghosts, while a
        // fresh lookup by number is exact.
        if !thread_alive_in_group(tgid, tid_hint) {
            return Err(format!(
                "tid {tid_hint} is not a live member of thread group {tgid}"
            ));
        }
        // Authoritative presence + pre-bracket, scoped to the group by the
        // path itself. A miss after tgkill passed means the member died in
        // the microsecond between the gates.
        let not_live = || format!("tid {tid_hint} is not a live member of thread group {tgid}");
        let (birth0, state0) = read_task_stat(tgid, tid_hint).map_err(|_| not_live())?;
        if state0 == 'Z' {
            return Err("retained member is a zombie, not a live survivor".to_string());
        }
        let member_dir = open_proc(&member_path(tgid, tid_hint))?;
        // Brackets through the held FD: the generation that was pre-checked
        // is the generation that was pinned (no TID reuse in between).
        let (birth1, state1) = read_relative_stat(member_dir.as_fd())
            .map_err(|error| format!("retained member proof unreadable during mint: {error}"))?;
        if birth1 != birth0 {
            return Err(
                "retained member birth changed between check and open (tid reuse)".to_string(),
            );
        }
        if state1 == 'Z' {
            return Err("retained member is a zombie, not a live survivor".to_string());
        }
        let member_tgid = read_relative_tgid(member_dir.as_fd())
            .map_err(|error| format!("retained member status unreadable during mint: {error}"))?;
        if member_tgid != tgid {
            return Err(format!("retained member is not in thread group {tgid}"));
        }
        // One live mint per slot; the minter Arc stays authoritative. Any
        // present entry refuses — a stale entry cannot exist because only
        // `Drop` removes one and every member drops.
        {
            let mut mints = LIVE_MINTS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(record) = mints.get(&(tgid, tid_hint)) {
                let same = record
                    .minter
                    .upgrade()
                    .is_some_and(|held| Arc::ptr_eq(&held, original));
                if same {
                    return Err("thread-group member already retained for this slot".to_string());
                }
                return Err(
                    "thread-group member already minted from a different original".to_string(),
                );
            }
            mints.insert(
                (tgid, tid_hint),
                MintRecord {
                    minter: Arc::downgrade(original),
                },
            );
        }
        drop(transient);
        Ok(Self {
            member_dir,
            _retained: retained,
            fd_owner: fd_owner.clone(),
            original: Arc::downgrade(original),
            tgid,
            tid: tid_hint,
            member_birth: birth1,
            leader_birth: leader_live,
        })
    }

    /// Re-prove the member: deadline, original authority, leader birth and
    /// member liveness plus birth. The thread group is pinned by the held
    /// FD, so the group check runs once at mint, not here.
    pub(crate) fn validate(&self, deadline: Instant) -> Result<(), String> {
        if Instant::now() >= deadline {
            return Err("retained member validation: deadline exhausted".to_string());
        }
        let _transient = self.fd_owner.batch().transient()?;
        match process_start_time(self.tgid) {
            Ok(birth) if birth == self.leader_birth => {}
            Ok(_) => {
                return Err(
                    "process generation changed during retained custody (pid reuse or exec)"
                        .to_string(),
                );
            }
            Err(_) => {
                return Err("original process exited during retained custody".to_string());
            }
        }
        self.live_identity()
    }

    /// The identity half of `validate` without deadline or budget: the
    /// member liveness plus birth proof behind `validate`, `selector` and
    /// the reads, so all entry points share one covered implementation.
    /// Runs under the caller's transient lease.
    fn live_identity(&self) -> Result<(), String> {
        let _original = self
            .original
            .upgrade()
            .ok_or_else(|| "original process custody was released".to_string())?;
        if !thread_alive_in_group(self.tgid, self.tid) {
            return Err("retained member is no longer alive".to_string());
        }
        let (birth, state) = read_relative_stat(self.member_dir.as_fd())
            .map_err(|error| format!("retained member is no longer alive: {error}"))?;
        if birth != self.member_birth {
            return Err(format!(
                "retained member birth changed (tid reuse): recorded {} live {birth}",
                self.member_birth
            ));
        }
        if state == 'Z' {
            return Err("retained member is a zombie, not a live survivor".to_string());
        }
        Ok(())
    }

    /// Select the member for a TID proof run, re-proving liveness first.
    /// Holds a transient lease for the proof I/O like every sibling read,
    /// so FD exhaustion refuses here instead of succeeding unleased.
    pub(crate) fn selector(&self) -> Result<ValidatedMemberSelector<'_>, String> {
        let _transient = self.fd_owner.batch().transient()?;
        self.live_identity()?;
        Ok(ValidatedMemberSelector { member: self })
    }

    /// The member exe identity off the held directory: the same shape as
    /// `caller_registry::read_exe_identity`, never through `caller_registry`.
    /// Refuses dead members instead of serving potentially stale bytes.
    pub(crate) fn read_exe_identity(&self) -> Option<ExeIdentity> {
        let _transient = self.fd_owner.batch().transient().ok()?;
        self.live_identity().ok()?;
        let exe = open_follow_relative(self.member_dir.as_fd(), c"exe")
            .map(std::fs::File::from)
            .ok()?;
        let metadata = exe.metadata().ok()?;
        Some(ExeIdentity {
            dev: metadata.dev(),
            ino: metadata.ino(),
            mtime_secs: metadata.mtime(),
            mtime_nanos: metadata.mtime_nsec(),
            path: read_link_relative(self.member_dir.as_fd(), c"exe"),
        })
    }

    /// The member maps file off the held directory. Refuses dead members
    /// instead of serving potentially stale bytes.
    pub(crate) fn open_maps(&self) -> std::io::Result<std::fs::File> {
        let _transient = self
            .fd_owner
            .batch()
            .transient()
            .map_err(std::io::Error::other)?;
        self.live_identity().map_err(std::io::Error::other)?;
        open_relative(self.member_dir.as_fd(), c"maps", false)
            .map(std::fs::File::from)
            .map_err(std::io::Error::other)
    }

    /// The member's map_files directory through the survivor's own
    /// TID-addressed process directory: `/proc/<tgid>/task/<tid>/` has no
    /// `map_files`, and for a zombie leader `/proc/<tgid>/map_files`
    /// serves nothing (the leader mm is gone) while `/proc/<tid>/`
    /// serves the shared mm. The TID directory is proved through its
    /// own dirfd (birth, Tgid, non-zombie) before `map_files` opens
    /// relative to it, so a TID reuse between the pre-open proof and
    /// the open refuses. Held transiently with its own lease; the
    /// member is re-proved before AND after the open.
    pub(crate) fn open_map_files_dir(&self) -> Result<TransientMapFilesDir, String> {
        self.open_map_files_dir_with_opener(&open_proc_dir)
    }

    /// `open_map_files_dir` with the TID process-directory opener injected.
    /// Production passes the real opener; tests inject a raced death so the
    /// post-open bracket is deterministic.
    pub(crate) fn open_map_files_dir_with_opener(
        &self,
        open_dir: &dyn Fn(&Path) -> Result<OwnedFd, String>,
    ) -> Result<TransientMapFilesDir, String> {
        let lease = self.fd_owner.batch().transient()?;
        self.live_identity()?;
        let proc = open_dir(&tid_proc_path(self.tid))?;
        // Bind through the same dirfd: a TID reuse between the pre-open
        // proof and the open reports another birth or group here, not
        // the member's map_files.
        let (birth, state) = read_relative_stat(proc.as_fd())
            .map_err(|error| format!("retained member is no longer alive: {error}"))?;
        if birth != self.member_birth {
            return Err(format!(
                "retained member birth changed (tid reuse): recorded {} live {birth}",
                self.member_birth
            ));
        }
        if state == 'Z' {
            return Err("retained member is a zombie, not a live survivor".to_string());
        }
        let proc_tgid = read_relative_tgid(proc.as_fd())
            .map_err(|error| format!("retained member is no longer alive: {error}"))?;
        if proc_tgid != self.tgid {
            return Err(format!(
                "retained member is not in thread group {}",
                self.tgid
            ));
        }
        let dir = open_relative(proc.as_fd(), c"map_files", true)?;
        // Post-open bracket: the member may have died between the proof
        // and the open. Both directories close with this refusal.
        self.live_identity()?;
        Ok(TransientMapFilesDir { dir, _lease: lease })
    }

    /// One range identity through the held map_files directory: the entry is
    /// followed, like `MapFilesDir::identity`.
    pub(crate) fn stat_map_file(&self, start: u64, end: u64) -> Result<FileIdentity, String> {
        self.stat_map_file_with_opener(start, end, &open_proc_dir)
    }

    /// `stat_map_file` with the TID process-directory opener injected.
    /// Production passes the real opener; tests inject a raced death so
    /// the post-open and post-stat brackets are deterministic.
    pub(crate) fn stat_map_file_with_opener(
        &self,
        start: u64,
        end: u64,
        open_dir: &dyn Fn(&Path) -> Result<OwnedFd, String>,
    ) -> Result<FileIdentity, String> {
        let guard = self.open_map_files_dir_with_opener(open_dir)?;
        self.stat_guarded(&guard, start, end)
    }

    /// Stat one range through a held guard, re-proving the member after
    /// the stat: the member may have died between the open and the stat.
    /// The proof runs even when the stat fails, so a dead member always
    /// reports the custody refusal instead of a stale lookup result.
    /// Shared by `stat_map_file` and the tests so the twin pins the code
    /// production runs.
    fn stat_guarded(
        &self,
        guard: &TransientMapFilesDir,
        start: u64,
        end: u64,
    ) -> Result<FileIdentity, String> {
        let stated = guard.stat(start, end);
        self.live_identity()?;
        stated
    }

    #[cfg(test)]
    pub(crate) fn test_stat_guarded(
        &self,
        guard: &TransientMapFilesDir,
        start: u64,
        end: u64,
    ) -> Result<FileIdentity, String> {
        self.stat_guarded(guard, start, end)
    }

    #[cfg(test)]
    pub(crate) fn test_recorded_births(&self) -> (u64, u64) {
        (self.member_birth, self.leader_birth)
    }

    #[cfg(test)]
    pub(crate) fn test_set_recorded_member_birth(&mut self, birth: u64) {
        self.member_birth = birth;
    }
}

/// True when `tid` names a live thread of `tgid` right now, via tgkill(2)
/// signal 0 (pid-namespace lookup), never /proc dentries: a held or listed
/// /proc entry can serve stale post-reap data through the RCU/dentry window,
/// while tgkill converges with the reclaim itself (death is monotonic, so
/// tests poll for convergence). EPERM still means alive (unpermitted, but
/// present); anything else means gone.
fn thread_alive_in_group(tgid: u32, tid: u32) -> bool {
    // SAFETY: signal 0 sends nothing; only the existence check runs.
    let done = unsafe { libc::tgkill(tgid as libc::pid_t, tid as libc::pid_t, 0) };
    if done == 0 {
        return true;
    }
    matches!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(code) if code == libc::EPERM
    )
}

fn member_path(tgid: u32, tid: u32) -> PathBuf {
    PathBuf::from(format!("/proc/{tgid}/task/{tid}"))
}

fn member_stat_path(tgid: u32, tid: u32) -> PathBuf {
    PathBuf::from(format!("/proc/{tgid}/task/{tid}/stat"))
}

fn tid_proc_path(tid: u32) -> PathBuf {
    PathBuf::from(format!("/proc/{tid}"))
}

/// Open a `/proc` directory: no symlinks, no inheritance, directory only.
fn open_proc_dir(path: &Path) -> Result<OwnedFd, String> {
    let path =
        CString::new(path.as_os_str().as_encoded_bytes()).map_err(|error| error.to_string())?;
    // SAFETY: a NUL-terminated internally built path; a new fd on success.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(format!(
            "opening {}: {}",
            path.to_string_lossy(),
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: open returned a newly owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Open one entry relative to a held `/proc` directory, never following a
/// symlink and never escaping through one.
fn open_relative(dir: BorrowedFd<'_>, name: &CStr, directory: bool) -> Result<OwnedFd, String> {
    let mut flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    if directory {
        flags |= libc::O_DIRECTORY;
    }
    // SAFETY: a live directory fd and a NUL-terminated internally chosen name.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(format!(
            "opening retained {}: {}",
            name.to_string_lossy(),
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: openat returned a newly owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Open one entry relative to a held directory, following it like `stat`
/// does (for `exe`, whose target carries the identity).
fn open_follow_relative(dir: BorrowedFd<'_>, name: &CStr) -> Result<OwnedFd, String> {
    // SAFETY: a live directory fd and a NUL-terminated internally chosen name.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(format!(
            "opening retained {}: {}",
            name.to_string_lossy(),
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: openat returned a newly owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Read one symlink relative to a held directory. The buffer is twice
/// `PATH_MAX`, which an exe link can never fill, so there is no truncation
/// branch to cover.
fn read_link_relative(dir: BorrowedFd<'_>, name: &CStr) -> Option<String> {
    let mut buf = [0u8; 8192];
    // SAFETY: a live directory fd, a valid name, and a writable buffer; the
    // call returns the link length without NUL-terminating it.
    let len = unsafe {
        libc::readlinkat(
            dir.as_raw_fd(),
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    if len < 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..len as usize]).into_owned())
}

/// A stat body as (start-time ticks, state char), parsed like
/// `process_start_time` (state first past the comm, start-time 19 after).
fn parse_stat(text: &str) -> Option<(u64, char)> {
    let end = text.rfind(')')?;
    let mut fields = text[end + 1..].split_whitespace();
    let state = fields.next()?.chars().next()?;
    let birth = fields.nth(18)?.parse::<u64>().ok()?;
    Some((birth, state))
}

fn read_task_stat(tgid: u32, tid: u32) -> Result<(u64, char), String> {
    let text = std::fs::read_to_string(member_stat_path(tgid, tid))
        .map_err(|error| format!("reading member stat: {error}"))?;
    parse_stat(&text).ok_or_else(|| "parsing member stat".to_string())
}

fn read_relative_stat(member_dir: BorrowedFd<'_>) -> Result<(u64, char), String> {
    use std::io::Read as _;
    let mut file = open_relative(member_dir, c"stat", false).map(std::fs::File::from)?;
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|error| format!("reading member stat: {error}"))?;
    parse_stat(&text).ok_or_else(|| "parsing member stat".to_string())
}

fn read_relative_tgid(member_dir: BorrowedFd<'_>) -> Result<u32, String> {
    use std::io::Read as _;
    let mut file = open_relative(member_dir, c"status", false).map(std::fs::File::from)?;
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|error| format!("reading member status: {error}"))?;
    text.lines()
        .find_map(|line| line.strip_prefix("Tgid:"))
        .and_then(|value| value.trim().parse::<u32>().ok())
        .ok_or_else(|| "parsing member status".to_string())
}

#[cfg(test)]
#[path = "retained_member_tests.rs"]
mod tests;
