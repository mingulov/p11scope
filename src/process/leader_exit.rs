//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Cold, bounded adjudication of a leader-exit hook under original custody.

use super::*;
use std::io::Read;
use std::time::{Duration, Instant};

const PF_EXITING: u32 = 0x0000_0004;
const STAT_BYTES: u64 = 4096;
const STATUS_BYTES: u64 = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LeaderExitObservation {
    GroupExited,
    LiveNonleader,
    Unresolved,
}

/// Shared by all pending exits in one publication; every directory entry
/// and bounded metadata operation consumes it. Exhaustion never proves absence.
pub(crate) struct LeaderExitReadBudget {
    remaining: u32,
    deadline: Instant,
}

impl LeaderExitReadBudget {
    pub(crate) fn for_commit() -> Self {
        Self::new(128, Instant::now() + Duration::from_millis(2))
    }

    /// One final-exit proof after a failed per-process operation: rare
    /// (failures only), so it may walk a few hundred task entries.
    pub(crate) fn for_final_exit_proof() -> Self {
        Self::new(512, Instant::now() + Duration::from_millis(20))
    }

    fn new(remaining: u32, deadline: Instant) -> Self {
        Self {
            remaining,
            deadline,
        }
    }

    pub(crate) fn spend(&mut self, units: u32) -> bool {
        if Instant::now() >= self.deadline || units > self.remaining {
            return false;
        }
        self.remaining -= units;
        true
    }

    #[cfg(test)]
    pub(crate) fn for_test(units: u32) -> Self {
        Self::new(units, Instant::now() + Duration::from_secs(10))
    }
}

#[derive(Clone, Copy)]
struct TaskStat {
    birth: u64,
    state: u8,
    flags: u32,
}

impl TaskStat {
    fn live_nonexiting(self) -> bool {
        matches!(
            self.state,
            b'R' | b'S' | b'D' | b'T' | b't' | b'I' | b'P' | b'W'
        ) && self.flags & PF_EXITING == 0
    }
}

trait ExitIo {
    type Tasks: Iterator<Item = Result<u32, ()>>;
    type Member;
    fn group_exited(&mut self) -> Result<bool, ()>;
    fn leader(&mut self) -> Result<TaskStat, ()>;
    fn tasks(&mut self) -> Result<Self::Tasks, ()>;
    fn hinted_member(&mut self, tid: u32) -> Result<TaskStat, ()>;
    fn open_member(&mut self, tid: u32) -> Result<Self::Member, ()>;
    fn member(&mut self, member: &Self::Member) -> Result<TaskStat, ()>;
    fn member_tgid(&mut self, member: &Self::Member) -> Result<u32, ()>;
}

fn observe_with<Io: ExitIo>(
    io: &mut Io,
    pid: u32,
    retained_birth: u64,
    work: &mut LeaderExitReadBudget,
) -> LeaderExitObservation {
    use LeaderExitObservation::*;
    if !work.spend(1) {
        return Unresolved;
    }
    match io.group_exited() {
        Ok(true) => return GroupExited,
        Ok(false) => {}
        Err(()) => return Unresolved,
    }
    if !work.spend(1)
        || !io
            .leader()
            .is_ok_and(|stat| stat.birth == retained_birth && stat.state == b'Z')
        || !work.spend(1)
    {
        return Unresolved;
    }
    let Ok(tasks) = io.tasks() else {
        return Unresolved;
    };
    for entry in tasks {
        if !work.spend(1) {
            return Unresolved;
        }
        let Ok(tid) = entry else {
            return Unresolved;
        };
        if tid == pid {
            continue;
        }
        if !work.spend(1) {
            return Unresolved;
        }
        let Ok(before) = io.hinted_member(tid) else {
            continue;
        };
        if !before.live_nonexiting() {
            continue;
        }
        if !work.spend(1) {
            return Unresolved;
        }
        let Ok(member) = io.open_member(tid) else {
            continue;
        };
        if !work.spend(2) {
            return Unresolved;
        }
        let (Ok(after), Ok(tgid)) = (io.member(&member), io.member_tgid(&member)) else {
            continue;
        };
        if before.birth != after.birth || !after.live_nonexiting() || tgid != pid {
            continue;
        }
        // The held member directory, its birth and original leader birth
        // close numeric reuse. A directory listing alone grants nothing.
        if !work.spend(3) {
            return Unresolved;
        }
        let (Ok(leader), Ok(final_member), Ok(exited)) =
            (io.leader(), io.member(&member), io.group_exited())
        else {
            return Unresolved;
        };
        if exited {
            return GroupExited;
        }
        if leader.birth == retained_birth
            && leader.state == b'Z'
            && final_member.birth == after.birth
            && final_member.live_nonexiting()
        {
            return LiveNonleader;
        }
    }
    // Empty/incomplete/raced task sets never prove a dead group. Only the
    // original pidfd can make that decision, including after the walk.
    if work.spend(1) && io.group_exited() == Ok(true) {
        GroupExited
    } else {
        Unresolved
    }
}

fn read_relative(
    directory: BorrowedFd<'_>,
    path: &std::ffi::CStr,
    limit: u64,
) -> Result<String, ()> {
    let fd = relative_proc_open(directory, path).map_err(|_| ())?;
    let mut bytes = Vec::new();
    std::fs::File::from(fd)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() as u64 > limit {
        return Err(());
    }
    String::from_utf8(bytes).map_err(|_| ())
}

fn stat_at(directory: BorrowedFd<'_>, path: &std::ffi::CStr) -> Result<TaskStat, ()> {
    let text = read_relative(directory, path, STAT_BYTES)?;
    let end = text.rfind(')').ok_or(())?;
    Ok(TaskStat {
        birth: start_time_from_stat(&text).map_err(|_| ())?,
        state: text[end + 1..]
            .split_whitespace()
            .next()
            .and_then(|v| v.as_bytes().first())
            .copied()
            .ok_or(())?,
        flags: stat_flags_from_stat_text(&text).ok_or(())?,
    })
}

struct OsExitIo<'a> {
    original: &'a PidPin,
    directory: ProcPin<'a>,
}

fn task_id(entry: io::Result<std::fs::DirEntry>) -> Result<u32, ()> {
    entry
        .map_err(|_| ())?
        .file_name()
        .to_string_lossy()
        .parse()
        .map_err(|_| ())
}

impl ExitIo for OsExitIo<'_> {
    type Tasks =
        std::iter::Map<std::fs::ReadDir, fn(io::Result<std::fs::DirEntry>) -> Result<u32, ()>>;
    type Member = OwnedFd;

    fn group_exited(&mut self) -> Result<bool, ()> {
        self.original.original_exited().map_err(|_| ())
    }
    fn leader(&mut self) -> Result<TaskStat, ()> {
        stat_at(self.directory.directory.as_fd(), c"stat")
    }
    fn tasks(&mut self) -> Result<Self::Tasks, ()> {
        let directory = std::fs::read_dir(format!(
            "/proc/self/fd/{}/task",
            self.directory.directory.as_raw_fd()
        ))
        .map_err(|_| ())?;
        Ok(directory.map(task_id))
    }
    fn hinted_member(&mut self, tid: u32) -> Result<TaskStat, ()> {
        let path = std::ffi::CString::new(format!("task/{tid}/stat")).map_err(|_| ())?;
        stat_at(self.directory.directory.as_fd(), &path)
    }
    fn open_member(&mut self, tid: u32) -> Result<Self::Member, ()> {
        let path = std::ffi::CString::new(format!("task/{tid}")).map_err(|_| ())?;
        relative_proc_open(self.directory.directory.as_fd(), &path).map_err(|_| ())
    }
    fn member(&mut self, member: &Self::Member) -> Result<TaskStat, ()> {
        stat_at(member.as_fd(), c"stat")
    }
    fn member_tgid(&mut self, member: &Self::Member) -> Result<u32, ()> {
        let text = read_relative(member.as_fd(), c"status", STATUS_BYTES)?;
        text.lines()
            .find_map(|line| line.strip_prefix("Tgid:"))
            .ok_or(())?
            .trim()
            .parse()
            .map_err(|_| ())
    }
}

impl PidPin {
    pub(crate) fn leader_exit_observation(
        &self,
        work: &mut LeaderExitReadBudget,
    ) -> LeaderExitObservation {
        // A start-time fallback cannot distinguish a zombie group from a
        // completed group. It never acquires new pidfd authority here.
        if self.pidfd().is_err() || !work.spend(1) {
            return LeaderExitObservation::Unresolved;
        }
        match self.original_exited() {
            Ok(true) => return LeaderExitObservation::GroupExited,
            Ok(false) => {}
            Err(_) => return LeaderExitObservation::Unresolved,
        }
        let Some(birth) = self.start_time() else {
            return LeaderExitObservation::Unresolved;
        };
        // Charge the existing retained-directory acquisition's bounded
        // opens/stat/pidfd brackets before any of them run.
        if !work.spend(8) {
            return LeaderExitObservation::Unresolved;
        }
        let Ok(directory) = self.open_proc_dir() else {
            return LeaderExitObservation::Unresolved;
        };
        observe_with(
            &mut OsExitIo {
                original: self,
                directory,
            },
            self.pid(),
            birth,
            work,
        )
    }
}

/// One task's exit-relevant state: its stat line.
#[derive(Clone, Copy)]
struct ExitingTask {
    stat: TaskStat,
    /// Stat field 20 (`num_threads`): the group's unreleased thread
    /// count, read under the task's `siglock` after its state field
    /// (`fs/proc/array.c` `do_task_stat`); 0 when the task was released
    /// mid-read. `None` when the field is malformed.
    threads: Option<u32>,
}

impl ExitingTask {
    /// Whether this task can never execute user code again: it is a
    /// zombie or dead, or it is already in `do_exit` (`PF_EXITING` is set
    /// there and never cleared). Both are irreversible. A merely pending
    /// `SIGKILL` does not count: a task running in user mode can execute
    /// a little more user code before the kernel takes the signal.
    fn past_user_mode(self) -> bool {
        self.dead() || self.stat.flags & PF_EXITING != 0
    }

    /// A zombie or dead state. Unlike `PF_EXITING` (the flags word is
    /// printed after the thread count), the state field is read before
    /// the count in the same `stat` read.
    fn dead(self) -> bool {
        matches!(self.stat.state, b'Z' | b'X' | b'x')
    }
}

trait FinalExitIo {
    type Tasks: Iterator<Item = Result<u32, ()>>;
    type Member;
    fn group_exited(&mut self) -> Result<bool, ()>;
    fn leader(&mut self) -> Result<ExitingTask, ()>;
    fn tasks(&mut self) -> Result<Self::Tasks, ()>;
    /// Open the member's `task/<tid>` directory and hold it. The handle
    /// pins the struct pid object, not the number (`free_pid` frees the
    /// number when the task detaches) and not the task: reads resolve
    /// the struct pid's task at read time, so a released member's reads
    /// fail, and a non-leader `exec` moves the leader's struct pid to
    /// the execing thread. `Ok(None)` only when the member is provably
    /// gone between the listing and this open (`ENOENT`/`ESRCH`); any
    /// other failure is `Err`.
    fn open_member(&mut self, tid: u32) -> Result<Option<Self::Member>, ()>;
    /// Read the held member's stat through its directory: whatever task
    /// owns the held struct pid now, never a recycled number's occupant.
    /// Any failure, including a release after the open, is `Err` and
    /// fails closed.
    fn member(&mut self, member: &Self::Member) -> Result<ExitingTask, ()>;
    /// The held member's `Tgid` through the same directory, so the stat
    /// and membership reads cannot straddle a reuse. Any failure is
    /// `Err` and fails closed.
    fn task_tgid(&mut self, member: &Self::Member) -> Result<u32, ()>;
}

/// Whether the retained thread group is in its final exit: either the
/// original pidfd reports the whole group gone, or the original leader
/// (same birth) and every member listed under it are past user mode.
///
/// A task in that state never runs user code again, so the group can make
/// no further provider call and no further `dlopen`. Thread creation needs
/// a creator that is not yet exiting, and the new thread is linked into
/// the group before `clone` returns to it.
///
/// The first walk opens each listed member's `task/<tid>` directory and
/// holds it; stat and `Tgid` are read through the held directory, so a
/// recycled number reads as a failure, never as a live occupant, and a
/// stat/status straddle cannot mix two threads. A member gone between
/// the first listing and its open stays out of the proven set: a tid
/// listed in the closing walk without a held handle fails.
///
/// The held directories alone do not prove the end: a non-leader `exec`
/// (`fs/exec.c` `de_thread`) moves the leader's struct pid to the
/// execing thread and copies the leader's start time into it, so the
/// held leader directory can describe a new, live task with the same
/// birth that creates a thread after the closing listing and then leaves
/// by a thread exit. Neither listing names that thread.
///
/// The closing step is therefore a thread census. The closing listing
/// is taken whole, then one leader `stat` read must show the original
/// birth, a zombie or dead state, and the group's unreleased thread count
/// `n` (read under the leader's `siglock`, after its state field, in the
/// same read; 0 when the leader was released mid-read). Every closing
/// tid is then re-read through its held handle after that count: same
/// birth, past user mode, `Tgid == pid`; a tid without a handle, or one
/// gone at its re-read, fails. A distinct non-leader member present
/// after the count was unreleased when it was taken, and every counted
/// thread is past user mode: the dead leader, and members proven past
/// in the first walk (past user mode is irreversible, and only the
/// leader's struct pid can change tasks, by an `exec` that a past task
/// cannot perform). So when those members number exactly `n - 1`, the
/// group had no live thread at the count and none can appear later:
/// thread creation and `exec` need a live thread in the group.
///
/// A leader still in `do_exit` (not yet a zombie) never proves the
/// census, because its `PF_EXITING` flag is printed after the count; the
/// pidfd proves such a group once the leader is a zombie and alone. Any
/// unreadable member, a reused leader, a count the members do not
/// account for, or an exhausted budget answers false: only a positive
/// proof counts.
fn final_exit_with<Io: FinalExitIo>(
    io: &mut Io,
    pid: u32,
    retained_birth: u64,
    work: &mut LeaderExitReadBudget,
) -> bool {
    if !work.spend(1) {
        return false;
    }
    match io.group_exited() {
        Ok(true) => return true,
        Ok(false) => {}
        Err(()) => return false,
    }
    let leader_dying = |io: &mut Io| {
        io.leader()
            .is_ok_and(|task| task.stat.birth == retained_birth && task.past_user_mode())
    };
    if !work.spend(1) || !leader_dying(io) || !work.spend(1) {
        return false;
    }
    let Ok(tasks) = io.tasks() else {
        return false;
    };
    // Every proven member by tid, with its birth and its held task
    // directory. A member already gone between the listing and its open
    // is left out: a tid that reappears in the closing listing without a
    // handle fails.
    let mut seen = std::collections::BTreeMap::new();
    for entry in tasks {
        if !work.spend(3) {
            return false;
        }
        let Ok(tid) = entry else {
            return false;
        };
        let held = match io.open_member(tid) {
            Ok(Some(held)) => held,
            Ok(None) => continue,
            Err(()) => return false,
        };
        match io.member(&held) {
            Ok(task) if task.past_user_mode() => {
                seen.insert(tid, (task.stat.birth, held));
            }
            Ok(_) | Err(()) => return false,
        }
    }
    // The closing listing, taken whole before the census count so every
    // re-read below happens after it.
    if !work.spend(1) {
        return false;
    }
    let Ok(again) = io.tasks() else {
        return false;
    };
    let mut closing = Vec::new();
    for entry in again {
        if !work.spend(1) {
            return false;
        }
        let Ok(tid) = entry else {
            return false;
        };
        closing.push(tid);
    }
    // The census count: one leader read with the original birth, a dead
    // state (read before the count) and the unreleased thread count.
    if !work.spend(1) {
        return false;
    }
    let threads = match io.leader() {
        Ok(leader) if leader.stat.birth == retained_birth && leader.dead() => leader.threads,
        Ok(_) | Err(()) => None,
    };
    let Some(threads) = threads.filter(|threads| *threads > 0) else {
        return false;
    };
    // Re-validate every closing tid through its held directory after the
    // count: a new tid, a recycled number, a recovered member, a member
    // that left this group, or a member gone at its re-read all fail.
    // Distinct non-leader members are counted once each.
    let mut counted = std::collections::BTreeSet::new();
    for tid in closing {
        if !work.spend(2) {
            return false;
        }
        let Some((first, held)) = seen.get(&tid) else {
            return false;
        };
        let Ok(task) = io.member(held) else {
            return false;
        };
        if task.stat.birth != *first || !task.past_user_mode() {
            return false;
        }
        if io.task_tgid(held) != Ok(pid) {
            return false;
        }
        if tid != pid {
            counted.insert(tid);
        }
    }
    // Every thread the count names is accounted for: the dead leader and
    // `n - 1` distinct members proven past.
    if counted.len() as u64 + 1 != u64::from(threads) {
        return false;
    }
    // Close the walk on the same original leader: a reused or recovered
    // leader never inherits the proof.
    if !work.spend(2) {
        return false;
    }
    io.group_exited() == Ok(true) || leader_dying(io)
}

fn read_relative_io(
    directory: BorrowedFd<'_>,
    path: &std::ffi::CStr,
    limit: u64,
) -> io::Result<String> {
    // SAFETY: live directory fd and NUL-terminated, internally selected path.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a newly owned fd.
    let file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::other("proc member exceeds its bound"));
    }
    String::from_utf8(bytes).map_err(io::Error::other)
}

fn open_task_dir(directory: BorrowedFd<'_>, tid: u32) -> Result<Option<OwnedFd>, ()> {
    let path = std::ffi::CString::new(format!("task/{tid}")).map_err(|_| ())?;
    // SAFETY: live directory fd and NUL-terminated, internally selected path.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound || error.raw_os_error() == Some(libc::ESRCH) {
            return Ok(None);
        }
        return Err(());
    }
    // SAFETY: openat returned a newly owned fd.
    Ok(Some(unsafe { OwnedFd::from_raw_fd(fd) }))
}

fn parse_exiting_task(stat: &str) -> Result<ExitingTask, ()> {
    let end = stat.rfind(')').ok_or(())?;
    Ok(ExitingTask {
        stat: TaskStat {
            birth: start_time_from_stat(stat).map_err(|_| ())?,
            state: stat[end + 1..]
                .split_whitespace()
                .next()
                .and_then(|v| v.as_bytes().first())
                .copied()
                .ok_or(())?,
            flags: stat_flags_from_stat_text(stat).ok_or(())?,
        },
        threads: stat[end + 1..]
            .split_whitespace()
            .nth(17)
            .and_then(|v| v.parse().ok()),
    })
}

impl FinalExitIo for OsExitIo<'_> {
    type Tasks =
        std::iter::Map<std::fs::ReadDir, fn(io::Result<std::fs::DirEntry>) -> Result<u32, ()>>;
    type Member = OwnedFd;

    fn group_exited(&mut self) -> Result<bool, ()> {
        self.original.original_exited().map_err(|_| ())
    }
    fn leader(&mut self) -> Result<ExitingTask, ()> {
        let directory = self.directory.directory.as_fd();
        let stat = read_relative_io(directory, c"stat", STAT_BYTES).map_err(|_| ())?;
        parse_exiting_task(&stat)
    }
    fn tasks(&mut self) -> Result<Self::Tasks, ()> {
        ExitIo::tasks(self)
    }
    fn open_member(&mut self, tid: u32) -> Result<Option<Self::Member>, ()> {
        open_task_dir(self.directory.directory.as_fd(), tid)
    }
    fn member(&mut self, member: &Self::Member) -> Result<ExitingTask, ()> {
        let stat = read_relative_io(member.as_fd(), c"stat", STAT_BYTES).map_err(|_| ())?;
        parse_exiting_task(&stat)
    }
    fn task_tgid(&mut self, member: &Self::Member) -> Result<u32, ()> {
        let text = read_relative_io(member.as_fd(), c"status", STATUS_BYTES).map_err(|_| ())?;
        text.lines()
            .find_map(|line| line.strip_prefix("Tgid:"))
            .ok_or(())?
            .trim()
            .parse()
            .map_err(|_| ())
    }
}

impl PidPin {
    /// Bounded final-exit proof for this retained generation (see
    /// `final_exit_with`). A start-time fallback pin never qualifies.
    pub(crate) fn final_exit_in_progress(&self, work: &mut LeaderExitReadBudget) -> bool {
        if self.pidfd().is_err() || !work.spend(1) {
            return false;
        }
        match self.original_exited() {
            Ok(true) => return true,
            Ok(false) => {}
            Err(_) => return false,
        }
        let Some(birth) = self.start_time() else {
            return false;
        };
        if !work.spend(8) {
            return false;
        }
        let Ok(directory) = self.open_proc_dir() else {
            return false;
        };
        final_exit_with(
            &mut OsExitIo {
                original: self,
                directory,
            },
            self.pid(),
            birth,
            work,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ScriptedIo {
        ready: bool,
        birth: u64,
        leader_state: u8,
        tids: Vec<Result<u32, ()>>,
        worker: TaskStat,
        tgid: u32,
        post_flags: Option<u32>,
        reads: usize,
    }
    impl ExitIo for ScriptedIo {
        type Tasks = std::vec::IntoIter<Result<u32, ()>>;
        type Member = ();
        fn group_exited(&mut self) -> Result<bool, ()> {
            Ok(self.ready)
        }
        fn leader(&mut self) -> Result<TaskStat, ()> {
            Ok(TaskStat {
                birth: self.birth,
                state: self.leader_state,
                flags: PF_EXITING,
            })
        }
        fn tasks(&mut self) -> Result<Self::Tasks, ()> {
            Ok(self.tids.clone().into_iter())
        }
        fn hinted_member(&mut self, _: u32) -> Result<TaskStat, ()> {
            Ok(self.worker)
        }
        fn open_member(&mut self, _: u32) -> Result<Self::Member, ()> {
            Ok(())
        }
        fn member(&mut self, _: &Self::Member) -> Result<TaskStat, ()> {
            self.reads += 1;
            let mut stat = self.worker;
            if self.reads > 1 {
                stat.flags = self.post_flags.unwrap_or(stat.flags);
            }
            Ok(stat)
        }
        fn member_tgid(&mut self, _: &Self::Member) -> Result<u32, ()> {
            Ok(self.tgid)
        }
    }
    fn io() -> ScriptedIo {
        ScriptedIo {
            ready: false,
            birth: 500,
            leader_state: b'Z',
            tids: vec![Ok(7), Ok(8)],
            worker: TaskStat {
                birth: 600,
                state: b'S',
                flags: 0,
            },
            tgid: 7,
            post_flags: None,
            reads: 0,
        }
    }
    fn observe(io: &mut ScriptedIo) -> LeaderExitObservation {
        observe_with(
            io,
            7,
            500,
            &mut LeaderExitReadBudget::new(128, Instant::now() + Duration::from_secs(1)),
        )
    }
    #[test]
    fn normal_single_thread_exit_waits_for_original_pidfd() {
        let mut source = io();
        source.tids = vec![Ok(7)];
        source.leader_state = b'R';
        assert_eq!(observe(&mut source), LeaderExitObservation::Unresolved);
        source.ready = true;
        assert_eq!(observe(&mut source), LeaderExitObservation::GroupExited);
    }
    #[test]
    fn early_hook_with_live_nonleader_waits_for_zombie_boundary() {
        let mut source = io();
        source.leader_state = b'R';
        assert_eq!(observe(&mut source), LeaderExitObservation::Unresolved);
        source.leader_state = b'Z';
        assert_eq!(observe(&mut source), LeaderExitObservation::LiveNonleader);
    }
    #[test]
    fn only_same_group_nonexiting_worker_proves_survival() {
        assert_eq!(observe(&mut io()), LeaderExitObservation::LiveNonleader);
        for (state, flags) in [(b'Z', 0), (b'X', 0), (b'R', PF_EXITING), (b'?', 0)] {
            let mut source = io();
            source.worker.state = state;
            source.worker.flags = flags;
            assert_eq!(observe(&mut source), LeaderExitObservation::Unresolved);
        }
        let mut wrong_group = io();
        wrong_group.tgid = 9;
        assert_eq!(observe(&mut wrong_group), LeaderExitObservation::Unresolved);
        let mut reused = io();
        reused.birth = 501;
        assert_eq!(observe(&mut reused), LeaderExitObservation::Unresolved);
        let mut exiting = io();
        exiting.post_flags = Some(PF_EXITING);
        assert_eq!(observe(&mut exiting), LeaderExitObservation::Unresolved);
    }
    #[test]
    fn read_and_time_bounds_never_become_survivor_proof() {
        for remaining in [0, 1, 3, 6, 9] {
            assert_eq!(
                observe_with(
                    &mut io(),
                    7,
                    500,
                    &mut LeaderExitReadBudget::new(
                        remaining,
                        Instant::now() + Duration::from_secs(1)
                    )
                ),
                LeaderExitObservation::Unresolved
            );
        }
        assert_eq!(
            observe_with(
                &mut io(),
                7,
                500,
                &mut LeaderExitReadBudget::new(128, Instant::now())
            ),
            LeaderExitObservation::Unresolved
        );
    }

    struct ScriptedFinalExit {
        exited: bool,
        leader: ExitingTask,
        members: Vec<(u32, Result<Option<ExitingTask>, ()>)>,
        reused_leader_after_walk: bool,
        leader_reads: usize,
        late_member: Option<u32>,
        reused_member: Option<(u32, ExitingTask)>,
        resurrected: Option<(u32, ExitingTask)>,
        gone_at_reread: Option<u32>,
        /// Seen in the first walk, released before the closing listing
        /// (omitted there, its held re-read fails).
        released_after_walk: Option<u32>,
        /// Listed twice by the closing listing.
        duplicate_in_closing: Option<u32>,
        /// The group's unreleased thread count every leader stat reports.
        leader_threads: u32,
        tgid: u32,
        listings: usize,
    }
    impl FinalExitIo for ScriptedFinalExit {
        type Tasks = std::vec::IntoIter<Result<u32, ()>>;
        type Member = u32;
        fn group_exited(&mut self) -> Result<bool, ()> {
            Ok(self.exited)
        }
        fn leader(&mut self) -> Result<ExitingTask, ()> {
            self.leader_reads += 1;
            let mut leader = self.leader;
            leader.threads = Some(self.leader_threads);
            if self.reused_leader_after_walk && self.leader_reads > 1 {
                leader.stat.birth += 1;
            }
            Ok(leader)
        }
        fn tasks(&mut self) -> Result<Self::Tasks, ()> {
            self.listings += 1;
            let mut tids = vec![Ok(7)];
            tids.extend(self.members.iter().filter_map(|(tid, task)| {
                // A released thread leaves the task list: the closing
                // listing omits it unless a new thread reused the tid
                // (scripted via `resurrected`).
                if self.listings > 1
                    && ((matches!(task, Ok(None))
                        && Some(*tid) != self.resurrected.map(|(resurrected, _)| resurrected))
                        || Some(*tid) == self.released_after_walk)
                {
                    None
                } else {
                    Some(Ok(*tid))
                }
            }));
            if self.listings > 1 {
                tids.extend(self.late_member.map(Ok));
                tids.extend(self.duplicate_in_closing.map(Ok));
                if let Some((resurrected, _)) = self.resurrected
                    && !self
                        .members
                        .iter()
                        .any(|(member, _)| *member == resurrected)
                {
                    tids.push(Ok(resurrected));
                }
            }
            Ok(tids.into_iter())
        }
        fn open_member(&mut self, tid: u32) -> Result<Option<Self::Member>, ()> {
            if tid == 7 {
                return Ok(Some(7));
            }
            match self.members.iter().find(|(member, _)| *member == tid) {
                Some((_, Ok(None))) => Ok(None),
                Some((_, Err(()))) => Err(()),
                Some((_, Ok(Some(_)))) => Ok(Some(tid)),
                None => Err(()),
            }
        }
        fn member(&mut self, member: &Self::Member) -> Result<ExitingTask, ()> {
            let tid = *member;
            if tid == 7 {
                return Ok(self.leader);
            }
            if self.listings > 1 && Some(tid) == self.released_after_walk {
                return Err(());
            }
            // A seen tid listed in the closing listing but released
            // before its re-read, after creating a child the closing
            // walk never lists: the held re-read fails and must fail
            // the proof closed.
            if self.listings > 1 && Some(tid) == self.gone_at_reread {
                return Err(());
            }
            // A tid recycled between the two listings: the first walk
            // reads the old past (or gone) member, the closing re-read
            // sees the live new thread under the same tid. Held task
            // directories pin the number against this reuse; the script
            // keeps the birth/liveness check as defense in depth.
            if self.listings > 1 {
                if let Some((reused, fresh)) = self.reused_member
                    && tid == reused
                {
                    return Ok(fresh);
                }
                if let Some((resurrected, fresh)) = self.resurrected
                    && tid == resurrected
                {
                    return Ok(fresh);
                }
            }
            match self.members.iter().find(|(member, _)| *member == tid) {
                Some((_, Ok(Some(task)))) => Ok(*task),
                Some((_, Ok(None))) | Some((_, Err(()))) | None => Err(()),
            }
        }
        fn task_tgid(&mut self, _member: &Self::Member) -> Result<u32, ()> {
            Ok(self.tgid)
        }
    }
    fn task(state: u8, flags: u32) -> ExitingTask {
        ExitingTask {
            stat: TaskStat {
                birth: 500,
                state,
                flags,
            },
            threads: None,
        }
    }
    fn dying_group() -> ScriptedFinalExit {
        ScriptedFinalExit {
            exited: false,
            leader: task(b'Z', PF_EXITING),
            members: vec![
                (8, Ok(Some(task(b'R', PF_EXITING)))),
                (9, Ok(Some(task(b'X', 0)))),
                (10, Ok(None)),
            ],
            reused_leader_after_walk: false,
            leader_reads: 0,
            late_member: None,
            reused_member: None,
            resurrected: None,
            gone_at_reread: None,
            released_after_walk: None,
            duplicate_in_closing: None,
            // The zombie leader plus the unreleased members 8 and 9.
            leader_threads: 3,
            tgid: 7,
            listings: 0,
        }
    }
    fn final_exit(io: &mut ScriptedFinalExit) -> bool {
        final_exit_with(io, 7, 500, &mut LeaderExitReadBudget::for_test(512))
    }
    #[test]
    fn group_past_user_mode_is_in_final_exit() {
        assert!(final_exit(&mut dying_group()));
        let mut single = dying_group();
        single.members.clear();
        single.leader_threads = 1;
        single.leader = task(b'Z', PF_EXITING);
        assert!(final_exit(&mut single), "a single zombie leader");
        // A single task still in do_exit is not a census proof (see
        // `a_leader_not_yet_a_zombie_never_proves_the_census`).
        single.leader = task(b'R', PF_EXITING);
        assert!(!final_exit(&mut single), "a single task still in do_exit");
        let mut exited = dying_group();
        exited.exited = true;
        exited.leader = task(b'S', 0);
        assert!(
            final_exit(&mut exited),
            "the original pidfd proves it outright"
        );
    }
    #[test]
    fn any_task_still_in_user_mode_keeps_the_group_live() {
        // A leader that left by pthread_exit while a worker runs.
        let mut worker = dying_group();
        worker.members.push((11, Ok(Some(task(b'S', 0)))));
        assert!(!final_exit(&mut worker));
        // An exec kill: the execing leader stays live.
        let mut exec = dying_group();
        exec.leader = task(b'R', 0);
        assert!(!final_exit(&mut exec));
        // An unreadable member is never proof.
        let mut unreadable = dying_group();
        unreadable.members.push((11, Err(())));
        assert!(!final_exit(&mut unreadable));
    }
    #[test]
    fn reused_leader_and_budgets_never_prove_final_exit() {
        let mut reused = dying_group();
        reused.leader.stat.birth = 501;
        assert!(!final_exit(&mut reused));
        let mut reused_late = dying_group();
        reused_late.reused_leader_after_walk = true;
        assert!(!final_exit(&mut reused_late));
        for units in [0, 1, 2, 4, 8] {
            assert!(
                !final_exit_with(
                    &mut dying_group(),
                    7,
                    500,
                    &mut LeaderExitReadBudget::for_test(units)
                ),
                "{units}"
            );
        }
    }
    #[test]
    fn pending_sigkill_alone_and_late_threads_never_prove_final_exit() {
        // A task that only has a fatal signal pending is still in user
        // mode until the kernel takes it: running, sleeping or stopped.
        for state in *b"RSDT" {
            let mut pending = dying_group();
            pending.members.push((11, Ok(Some(task(state, 0)))));
            assert!(!final_exit(&mut pending), "{}", state as char);
        }
        // A thread created while the first listing ran fails the proof.
        let mut late = dying_group();
        late.late_member = Some(12);
        assert!(!final_exit(&mut late));
        assert_eq!(late.listings, 2, "the task list is read twice");
        let parsed =
            parse_exiting_task("7 (x) R 1 7 7 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 500 0 0")
                .unwrap();
        assert_eq!(parsed.stat.birth, 500);
        assert!(!parsed.past_user_mode());
        assert!(
            parse_exiting_task("7 (x").is_err(),
            "a torn stat is not proof"
        );
    }
    #[test]
    fn reused_member_tid_backed_by_a_live_thread_never_proves_final_exit() {
        // A member tid released after its past read and recycled by a
        // live new thread before the closing listing: the tid is
        // already in the seen set, but the birth changed and the new
        // thread runs user code, so the proof must fail.
        let mut reused = dying_group();
        reused.reused_member = Some((
            8,
            ExitingTask {
                stat: TaskStat {
                    birth: 501,
                    state: b'S',
                    flags: 0,
                },
                threads: None,
            },
        ));
        assert!(
            !final_exit(&mut reused),
            "a recycled member tid with a live new thread keeps the group unproven"
        );
        assert_eq!(reused.listings, 2, "the task list is read twice");
        // A tid that was already gone in the first walk and reappears
        // in the closing listing is a new thread, never the released
        // one.
        let mut resurrected = dying_group();
        resurrected.resurrected = Some((
            10,
            ExitingTask {
                stat: TaskStat {
                    birth: 502,
                    state: b'S',
                    flags: 0,
                },
                threads: None,
            },
        ));
        assert!(
            !final_exit(&mut resurrected),
            "a gone tid that reappears is a new thread"
        );
        // A member that left this group between the two listings fails
        // the proof even when its birth and state still read past.
        let mut foreign = dying_group();
        foreign.tgid = 9;
        assert!(
            !final_exit(&mut foreign),
            "a member outside this group keeps the proof unproven"
        );
    }
    #[test]
    fn listed_member_gone_at_the_closing_re_read_after_spawning_keeps_the_group_unproven() {
        // A seen tid listed in the closing listing, released before
        // its re-read after creating a child the closing walk never
        // lists (created after the last directory read): the held
        // re-read fails while a live thread runs, so the proof must
        // fail. Accepting the release would prove an exit with a live
        // creator's child unlisted.
        let mut gone = dying_group();
        gone.gone_at_reread = Some(8);
        assert!(
            !final_exit(&mut gone),
            "a listed-but-gone member after child creation keeps the group unproven"
        );
        assert_eq!(gone.listings, 2, "the task list is read twice");
    }
    /// A non-leader `exec` moves the leader's struct pid (the TGID) to
    /// the execing thread and copies the leader's start time into it
    /// (`fs/exec.c` `de_thread`), so the held leader directory follows
    /// the new task: birth and `Tgid` still match, and once that task
    /// leaves by a thread exit it reads past. A live thread it created
    /// after the closing listing is in neither listing; only the
    /// group's unreleased-thread count shows it, so the proof must fail.
    #[test]
    fn non_leader_exec_with_an_unlisted_live_thread_keeps_the_group_unproven() {
        let exec = || {
            let mut exec = dying_group();
            // Member 8 was seen past, then released before the closing
            // listing (the exec reaps every other thread).
            exec.members = vec![(8, Ok(Some(task(b'R', PF_EXITING))))];
            exec.released_after_walk = Some(8);
            exec
        };
        let mut live = exec();
        // The execing thread, now the zombie leader, plus its live,
        // unlisted thread.
        live.leader_threads = 2;
        assert!(
            !final_exit(&mut live),
            "an exec-transferred leader with an unlisted live thread keeps the group unproven"
        );
        // Healthy twin: the zombie leader is the group's only thread.
        let mut alone = exec();
        alone.leader_threads = 1;
        assert!(
            final_exit(&mut alone),
            "a zombie leader alone in its group is the final exit"
        );
    }

    /// The thread count read with the zombie leader must be fully
    /// accounted for by distinct held members still present after it:
    /// an extra unreleased thread, a duplicated listing entry, or a
    /// leader released mid-read never proves the exit.
    #[test]
    fn thread_census_must_account_for_every_unreleased_thread() {
        assert!(final_exit(&mut dying_group()), "the exact census proves");
        let mut extra = dying_group();
        extra.leader_threads = 4;
        assert!(
            !final_exit(&mut extra),
            "an unlisted unreleased thread keeps the group unproven"
        );
        let mut duplicate = dying_group();
        duplicate.leader_threads = 4;
        duplicate.duplicate_in_closing = Some(8);
        assert!(
            !final_exit(&mut duplicate),
            "a member listed twice counts once"
        );
        let mut released = dying_group();
        released.leader_threads = 0;
        assert!(
            !final_exit(&mut released),
            "a count read after the leader's release is no census"
        );
        let parsed =
            parse_exiting_task("7 (x) Z 1 7 7 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 3 0 500 0 0")
                .unwrap();
        assert_eq!(parsed.threads, Some(3), "stat field 20");
        let torn =
            parse_exiting_task("7 (x) Z 1 7 7 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 x 0 500 0 0")
                .unwrap();
        assert_eq!(torn.threads, None, "a malformed count is no count");
    }

    /// The count is read after the state field but before the flags
    /// word, so only a dead state (zombie) proves the census: a leader
    /// still in `do_exit` could have created a thread between the two
    /// fields. Such a group stays unproven until the leader is a zombie
    /// (or the pidfd reports the end).
    #[test]
    fn a_leader_not_yet_a_zombie_never_proves_the_census() {
        let mut single = dying_group();
        single.members.clear();
        single.leader = task(b'R', PF_EXITING);
        single.leader_threads = 1;
        assert!(
            !final_exit(&mut single),
            "a lone leader still in do_exit is unproven"
        );
        single.leader = task(b'Z', PF_EXITING);
        assert!(final_exit(&mut single), "a lone zombie leader proves");
        let mut exiting = dying_group();
        exiting.leader = task(b'D', PF_EXITING);
        assert!(
            !final_exit(&mut exiting),
            "an exiting, non-zombie leader is unproven"
        );
    }

    /// Real `/proc` reproducer of the non-leader `exec` identity
    /// transfer: the leader leaves by `pthread_exit`, a worker execs,
    /// and the new image (now the leader under the original pid with
    /// the original start time) creates a blocked thread and leaves by
    /// `pthread_exit` too. The held leader task directory follows the
    /// execing thread. The proof runs against the real kernel state
    /// with the live thread hidden from both listings — what a thread
    /// created after the closing listing looks like — and must fail.
    #[test]
    fn real_non_leader_exec_with_a_hidden_live_thread_keeps_the_group_unproven() {
        let step = std::sync::Arc::new(std::sync::Mutex::new("start"));
        let (done, result) = std::sync::mpsc::channel();
        let body_step = std::sync::Arc::clone(&step);
        std::thread::spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                exec_transfer_walk(&body_step)
            }));
            let _ = done.send(outcome);
        });
        match result.recv_timeout(Duration::from_secs(60)) {
            Ok(Ok(())) => {}
            Ok(Err(panic)) => std::panic::resume_unwind(panic),
            Err(_) => panic!(
                "the exec-transfer walk did not finish within 60 s; stuck at: {}",
                step.lock().unwrap()
            ),
        }
    }

    /// The real OS proof IO with one tid hidden from every listing.
    struct HidingIo<'a> {
        inner: OsExitIo<'a>,
        hidden: u32,
    }
    impl FinalExitIo for HidingIo<'_> {
        type Tasks = std::vec::IntoIter<Result<u32, ()>>;
        type Member = OwnedFd;
        fn group_exited(&mut self) -> Result<bool, ()> {
            FinalExitIo::group_exited(&mut self.inner)
        }
        fn leader(&mut self) -> Result<ExitingTask, ()> {
            FinalExitIo::leader(&mut self.inner)
        }
        fn tasks(&mut self) -> Result<Self::Tasks, ()> {
            let hidden = self.hidden;
            Ok(FinalExitIo::tasks(&mut self.inner)?
                .filter(|tid| *tid != Ok(hidden))
                .collect::<Vec<_>>()
                .into_iter())
        }
        fn open_member(&mut self, tid: u32) -> Result<Option<Self::Member>, ()> {
            FinalExitIo::open_member(&mut self.inner, tid)
        }
        fn member(&mut self, member: &Self::Member) -> Result<ExitingTask, ()> {
            FinalExitIo::member(&mut self.inner, member)
        }
        fn task_tgid(&mut self, member: &Self::Member) -> Result<u32, ()> {
            FinalExitIo::task_tgid(&mut self.inner, member)
        }
    }

    /// Kills and reaps the exec fixture on every exit path.
    struct ExecGroup(Option<std::process::Child>);
    impl Drop for ExecGroup {
        fn drop(&mut self) {
            if let Some(mut child) = self.0.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    fn task_tids(pid: u32) -> Vec<u32> {
        let mut tids: Vec<u32> = std::fs::read_dir(format!("/proc/{pid}/task"))
            .map(|entries| {
                entries
                    .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse().ok())
                    .collect()
            })
            .unwrap_or_default();
        tids.sort_unstable();
        tids
    }

    fn exec_transfer_walk(step: &std::sync::Mutex<&'static str>) {
        use std::io::Write as _;
        use std::os::unix::process::CommandExt as _;
        let at = |name: &'static str| *step.lock().unwrap() = name;

        at("build the fixture");
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("mt-exec.c");
        let executable = dir.path().join("mt-exec");
        std::fs::write(&source, MT_EXEC_SOURCE).unwrap();
        let built = std::process::Command::new("cc")
            .args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread", "-O1"])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap();
        assert!(built.success(), "fixture build failed: {built}");

        at("spawn the fixture");
        let (gate_r, mut gate_w) = std::io::pipe().unwrap();
        let (release_r, mut release_w) = std::io::pipe().unwrap();
        let (gate_raw, release_raw) = (gate_r.as_raw_fd(), release_r.as_raw_fd());
        let mut command = std::process::Command::new(&executable);
        command
            .args(["before", &gate_raw.to_string(), &release_raw.to_string()])
            .stdout(std::process::Stdio::piped());
        // SAFETY: only async-signal-safe prctl/fcntl before exec.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong) != 0
                    || libc::fcntl(gate_raw, libc::F_SETFD, 0) != 0
                    || libc::fcntl(release_raw, libc::F_SETFD, 0) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        drop((gate_r, release_r));
        let pid = child.id();
        let mut stdout = child.stdout.take().unwrap();
        let mut group = ExecGroup(Some(child));
        let pin = PidPin::open(pid).unwrap();
        assert!(pin.pidfd().is_ok(), "the proof needs a pidfd pin");
        let birth = pin.start_time().expect("the pin retains the birth");

        let wait_for = |what: &'static str, done: &dyn Fn() -> bool| {
            at(what);
            let deadline = Instant::now() + Duration::from_secs(10);
            while !done() {
                assert!(Instant::now() < deadline, "timed out: {what}");
                std::thread::sleep(Duration::from_millis(1));
            }
        };
        wait_for("zombie leader with the gated worker", &|| {
            crate::process::process_is_zombie(pid) && task_tids(pid).len() == 2
        });
        let before = task_tids(pid);
        let worker = *before.iter().find(|tid| **tid != pid).unwrap();
        // Hold the leader's task directory across the exec.
        let held = open_task_dir(pin.open_proc_dir().unwrap().directory.as_fd(), pid)
            .unwrap()
            .expect("the zombie leader's task directory opens");
        let read_held = || {
            parse_exiting_task(&read_relative_io(held.as_fd(), c"stat", STAT_BYTES).unwrap())
                .unwrap()
        };
        let old = read_held();
        assert_eq!(old.stat.state, b'Z');
        assert_eq!(old.stat.birth, birth);
        assert!(
            !pin.final_exit_in_progress(&mut LeaderExitReadBudget::for_test(512)),
            "a live worker keeps the zombie-leader group live"
        );

        at("non-leader exec");
        gate_w.write_all(&[1]).unwrap();
        let mut ready = [0u8; 1];
        stdout.read_exact(&mut ready).unwrap();
        assert_eq!(ready, *b"R", "the new image is up");
        wait_for("exec'd leader leaves, its thread lives", &|| {
            let tids = task_tids(pid);
            crate::process::process_is_zombie(pid) && tids.len() == 2 && !tids.contains(&worker)
        });
        let after = task_tids(pid);
        let live = *after.iter().find(|tid| **tid != pid).unwrap();

        at("held leader follows the execing thread");
        let new = read_held();
        assert_eq!(
            new.stat.state, b'Z',
            "the exec'd leader left by pthread_exit"
        );
        assert_eq!(
            new.stat.birth, birth,
            "de_thread copies the leader's start time"
        );
        assert_eq!(new.threads, Some(2), "the count sees the live thread");
        assert_eq!(pin.original_exited(), Ok(false), "the group lives");

        at("proof with the live thread hidden");
        let mut hiding = HidingIo {
            inner: OsExitIo {
                original: &pin,
                directory: pin.open_proc_dir().unwrap(),
            },
            hidden: live,
        };
        assert!(
            !final_exit_with(
                &mut hiding,
                pid,
                birth,
                &mut LeaderExitReadBudget::for_test(512)
            ),
            "an unlisted live thread after a non-leader exec keeps the group unproven"
        );
        assert!(
            !pin.final_exit_in_progress(&mut LeaderExitReadBudget::for_test(512)),
            "the listed live thread keeps the group live"
        );

        at("release the live thread");
        release_w.write_all(&[1]).unwrap();
        let mut child = group.0.take().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "the group never ended");
            std::thread::sleep(Duration::from_millis(1));
        };
        assert!(status.success(), "{status}");
        assert_eq!(pin.original_exited(), Ok(true));
    }

    /// `before GATE RELEASE`: the leader leaves by `pthread_exit` while a
    /// worker waits on GATE, then execs this binary as `after`. `after`:
    /// now the leader, it starts a thread blocked on RELEASE (which then
    /// ends the group with status 0), reports `R` and leaves by
    /// `pthread_exit`.
    const MT_EXEC_SOURCE: &str = r#"
#define _GNU_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char *gate_arg;
static char *release_arg;

static void *execer(void *arg) {
    (void)arg;
    char byte;
    if (read(atoi(gate_arg), &byte, 1) != 1) _exit(20);
    char *const argv[] = {"mt-exec", "after", gate_arg, release_arg, NULL};
    /* /proc/self/exe follows the zombie leader, which has no mm. */
    execv("/proc/thread-self/exe", argv);
    _exit(21);
}

static void *blocker(void *arg) {
    (void)arg;
    char byte;
    if (read(atoi(release_arg), &byte, 1) != 1) _exit(22);
    _exit(0);
}

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    gate_arg = argv[2];
    release_arg = argv[3];
    pthread_t thread;
    if (strcmp(argv[1], "before") == 0) {
        if (pthread_create(&thread, NULL, execer, NULL)) return 3;
    } else {
        if (pthread_create(&thread, NULL, blocker, NULL)) return 4;
        if (write(STDOUT_FILENO, "R", 1) != 1) return 5;
    }
    pthread_exit(NULL);
}
"#;

    #[test]
    fn real_live_group_is_not_in_final_exit_until_it_exits() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pin = PidPin::open(child.id()).unwrap();
        assert!(pin.pidfd().is_ok(), "the proof needs a pidfd pin");
        assert!(!pin.final_exit_in_progress(&mut LeaderExitReadBudget::for_test(512)));
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(pin.final_exit_in_progress(&mut LeaderExitReadBudget::for_test(512)));
    }

    /// The real `/proc` walk arm of the final-exit proof, against a real
    /// multi-threaded child traced so each thread can be held at its exit
    /// stop. The leader leaves through `pthread_exit` (a zombie while its
    /// workers live); the walk proves the group ending only once the last
    /// worker is past user mode (here an unreaped traced zombie), before
    /// the pidfd turns ready.
    ///
    /// Every wait is bounded, and the body runs on its own thread under a
    /// hard deadline, so a stuck step fails with its name instead of
    /// hanging the run.
    #[test]
    fn real_proc_walk_proves_final_exit_only_once_every_thread_is_past_user_mode() {
        let step = std::sync::Arc::new(std::sync::Mutex::new("start"));
        let (done, result) = std::sync::mpsc::channel();
        let body_step = std::sync::Arc::clone(&step);
        std::thread::spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                traced_exit_walk(&body_step)
            }));
            let _ = done.send(outcome);
        });
        match result.recv_timeout(Duration::from_secs(60)) {
            Ok(Ok(())) => {}
            Ok(Err(panic)) => std::panic::resume_unwind(panic),
            Err(_) => panic!(
                "the traced exit walk did not finish within 60 s; stuck at: {}",
                step.lock().unwrap()
            ),
        }
    }

    /// Bounded `waitpid(tid, __WALL)`: polls with `WNOHANG` until `tid`
    /// reports or `within` passes.
    fn wait_tid_within(tid: libc::pid_t, within: Duration, what: &str) -> libc::c_int {
        let deadline = Instant::now() + within;
        loop {
            let mut status: libc::c_int = 0;
            // SAFETY: a writable status word; `tid` is our traced task.
            let rc = unsafe { libc::waitpid(tid, &mut status, libc::__WALL | libc::WNOHANG) };
            if rc == tid {
                return status;
            }
            if rc < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                panic!("waitpid({tid}) for {what} failed: {error}");
            }
            assert!(
                Instant::now() < deadline,
                "no wait status from {tid} for {what} within {within:?}"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[cfg(any(target_env = "gnu", target_env = "uclibc"))]
    type PtraceRequest = libc::c_uint;
    #[cfg(not(any(target_env = "gnu", target_env = "uclibc")))]
    type PtraceRequest = libc::c_int;

    fn ptrace_op(request: PtraceRequest, tid: libc::pid_t, data: usize) {
        // SAFETY: `tid` is stopped under our ptrace; `data` is valid for
        // the request (a flag word or a writable `c_ulong`).
        let rc = unsafe { libc::ptrace(request, tid, 0usize, data) };
        assert!(
            rc >= 0,
            "ptrace({request}, {tid}) failed: {}",
            io::Error::last_os_error()
        );
    }

    fn wait_exit_event(tid: libc::pid_t, event: libc::c_int, what: &str) {
        let status = wait_tid_within(tid, Duration::from_secs(10), what);
        assert!(
            libc::WIFSTOPPED(status)
                && libc::WSTOPSIG(status) == libc::SIGTRAP
                && (status >> 16) & 0xffff == event,
            "{what}: unexpected wait status {status:#x} from {tid}"
        );
    }

    /// Kills and reaps the traced group with bounded waits, so a failed
    /// assertion never leaves traced zombies that block the leader's reap.
    struct TracedGroup {
        leader: libc::pid_t,
        tids: Vec<libc::pid_t>,
        child: Option<std::process::Child>,
    }
    impl Drop for TracedGroup {
        fn drop(&mut self) {
            let Some(mut child) = self.child.take() else {
                return;
            };
            // SAFETY: signalling our own child's thread group.
            unsafe { libc::kill(self.leader, libc::SIGKILL) };
            let deadline = Instant::now() + Duration::from_secs(10);
            // Workers first: a traced zombie worker keeps the leader
            // unreapable until its tracer reaps it.
            let leader = self.leader;
            for tid in self.tids.drain(..).chain(std::iter::once(leader)) {
                loop {
                    let mut status: libc::c_int = 0;
                    // SAFETY: a writable status word; reaping our tracee.
                    let rc =
                        unsafe { libc::waitpid(tid, &mut status, libc::__WALL | libc::WNOHANG) };
                    let exited = libc::WIFEXITED(status) || libc::WIFSIGNALED(status);
                    if rc < 0 || (rc == tid && exited) || Instant::now() >= deadline {
                        break;
                    }
                    if rc == tid {
                        // A stop reported while dying: let it go on.
                        // SAFETY: `tid` is stopped under our ptrace.
                        unsafe { libc::ptrace(libc::PTRACE_CONT, tid, 0usize, 0usize) };
                        continue;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            while Instant::now() < deadline && matches!(child.try_wait(), Ok(None)) {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    fn traced_exit_walk(step: &std::sync::Mutex<&'static str>) {
        use std::io::Write as _;
        use std::os::unix::process::CommandExt as _;
        let at = |name: &'static str| *step.lock().unwrap() = name;

        at("build the fixture");
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("mt-exit.c");
        let executable = dir.path().join("mt-exit");
        std::fs::write(&source, MT_EXIT_SOURCE).unwrap();
        let built = std::process::Command::new("cc")
            .args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread", "-O1"])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .status()
            .unwrap();
        assert!(built.success(), "fixture build failed: {built}");

        at("spawn the traced child");
        let (r0, mut w0) = std::io::pipe().unwrap();
        let (r1, mut w1) = std::io::pipe().unwrap();
        let (r0_raw, r1_raw) = (r0.as_raw_fd(), r1.as_raw_fd());
        let mut command = std::process::Command::new(&executable);
        command
            .args([r0_raw.to_string(), r1_raw.to_string()])
            .stdout(std::process::Stdio::piped());
        // SAFETY: only async-signal-safe prctl/fcntl/ptrace before exec.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL as libc::c_ulong) != 0
                    || libc::fcntl(r0_raw, libc::F_SETFD, 0) != 0
                    || libc::fcntl(r1_raw, libc::F_SETFD, 0) != 0
                    || libc::ptrace(libc::PTRACE_TRACEME, 0, 0usize, 0usize) < 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        drop((r0, r1));
        let leader = child.id() as libc::pid_t;
        let mut stdout = child.stdout.take().unwrap();
        let mut group = TracedGroup {
            leader,
            tids: Vec::new(),
            child: Some(child),
        };

        at("exec stop");
        let exec_stop = wait_tid_within(leader, Duration::from_secs(10), "the exec stop");
        assert!(
            libc::WIFSTOPPED(exec_stop) && libc::WSTOPSIG(exec_stop) == libc::SIGTRAP,
            "exec stop {exec_stop:#x}"
        );
        ptrace_op(
            libc::PTRACE_SETOPTIONS,
            leader,
            (libc::PTRACE_O_TRACECLONE | libc::PTRACE_O_TRACEEXIT | libc::PTRACE_O_EXITKILL)
                as usize,
        );
        ptrace_op(libc::PTRACE_CONT, leader, 0);
        for _ in 0..2 {
            at("worker clone");
            wait_exit_event(leader, libc::PTRACE_EVENT_CLONE, "a worker clone");
            let mut new_tid: libc::c_ulong = 0;
            ptrace_op(
                libc::PTRACE_GETEVENTMSG,
                leader,
                std::ptr::from_mut(&mut new_tid) as usize,
            );
            let tid = new_tid as libc::pid_t;
            group.tids.push(tid);
            at("worker start stop");
            let stop = wait_tid_within(tid, Duration::from_secs(10), "the worker start stop");
            assert!(
                libc::WIFSTOPPED(stop) && libc::WSTOPSIG(stop) == libc::SIGSTOP,
                "worker start {stop:#x}"
            );
            ptrace_op(libc::PTRACE_CONT, tid, 0);
            ptrace_op(libc::PTRACE_CONT, leader, 0);
        }
        let (tid0, tid1) = (group.tids[0], group.tids[1]);

        at("workers ready");
        let mut poll = libc::pollfd {
            fd: stdout.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd.
        assert_eq!(unsafe { libc::poll(&mut poll, 1, 10_000) }, 1, "ready byte");
        let mut ready = [0u8; 1];
        stdout.read_exact(&mut ready).unwrap();
        assert_eq!(ready, *b"R");

        at("leader exit");
        wait_exit_event(leader, libc::PTRACE_EVENT_EXIT, "the leader exit");
        ptrace_op(libc::PTRACE_CONT, leader, 0);
        let deadline = Instant::now() + Duration::from_secs(10);
        while !crate::process::process_is_zombie(leader as u32) {
            assert!(
                Instant::now() < deadline,
                "the leader never became a zombie"
            );
            std::thread::sleep(Duration::from_millis(1));
        }

        at("proof with two live workers");
        let pin = PidPin::open(leader as u32).unwrap();
        assert!(pin.pidfd().is_ok(), "the proof needs a pidfd pin");
        assert_eq!(pin.original_exited(), Ok(false));
        assert!(
            !pin.final_exit_in_progress(&mut LeaderExitReadBudget::for_test(512)),
            "two live workers keep the zombie-leader group live"
        );

        at("first worker exit");
        w0.write_all(&[1]).unwrap();
        wait_exit_event(tid0, libc::PTRACE_EVENT_EXIT, "worker 0 exit");
        ptrace_op(libc::PTRACE_CONT, tid0, 0);
        let status0 = wait_tid_within(tid0, Duration::from_secs(10), "worker 0 reap");
        assert!(libc::WIFEXITED(status0), "worker 0 {status0:#x}");
        group.tids.retain(|tid| *tid != tid0);
        at("proof with one live worker");
        assert_eq!(pin.original_exited(), Ok(false));
        assert!(
            !pin.final_exit_in_progress(&mut LeaderExitReadBudget::for_test(512)),
            "one live worker keeps the group live"
        );

        // A thread stopped at its exit event has not yet set
        // `PF_EXITING` (the kernel reports the event first), so it is not
        // proof; once it runs on, an unreaped traced worker stays a
        // zombie on the group's thread list, keeping the pidfd unready.
        at("last worker held at its exit event");
        w1.write_all(&[1]).unwrap();
        wait_exit_event(tid1, libc::PTRACE_EVENT_EXIT, "worker 1 exit");
        assert_eq!(pin.original_exited(), Ok(false));
        assert!(
            !pin.final_exit_in_progress(&mut LeaderExitReadBudget::for_test(512)),
            "a worker stopped before PF_EXITING is not past user mode"
        );
        at("last worker an unreaped zombie");
        ptrace_op(libc::PTRACE_CONT, tid1, 0);
        let stat = format!("/proc/{leader}/task/{tid1}/stat");
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let text = std::fs::read_to_string(&stat).unwrap_or_default();
            let state = text
                .rfind(')')
                .and_then(|end| text[end + 1..].split_whitespace().next())
                .unwrap_or("");
            if state == "Z" {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "worker 1 never became a zombie: {text:?}"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            pin.original_exited(),
            Ok(false),
            "an unreaped worker keeps the pidfd unready"
        );
        at("proof with every thread past user mode");
        assert!(
            pin.final_exit_in_progress(&mut LeaderExitReadBudget::for_test(512)),
            "the /proc walk proves the final exit before the pidfd is ready"
        );

        at("group reap");
        let status1 = wait_tid_within(tid1, Duration::from_secs(10), "worker 1 reap");
        assert!(libc::WIFEXITED(status1), "worker 1 {status1:#x}");
        group.tids.clear();
        let mut child = group.child.take().unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "the leader was never reapable");
            std::thread::sleep(Duration::from_millis(1));
        };
        assert!(status.success(), "{status}");
        assert_eq!(pin.original_exited(), Ok(true));
    }

    const MT_EXIT_SOURCE: &str = r#"
#define _GNU_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

static pthread_mutex_t gate = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static unsigned ready = 0;

static void *worker(void *arg) {
    int fd = *(int *)arg;
    if (pthread_mutex_lock(&gate)) _exit(10);
    ready++;
    if (pthread_cond_broadcast(&changed)) _exit(11);
    if (pthread_mutex_unlock(&gate)) _exit(12);
    char byte;
    if (read(fd, &byte, 1) != 1) _exit(13);
    syscall(SYS_exit, 0);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    static int fds[2];
    fds[0] = atoi(argv[1]);
    fds[1] = atoi(argv[2]);
    pthread_t t0, t1;
    if (pthread_create(&t0, NULL, worker, &fds[0])) return 3;
    if (pthread_create(&t1, NULL, worker, &fds[1])) return 4;
    if (pthread_mutex_lock(&gate)) return 5;
    while (ready != 2)
        if (pthread_cond_wait(&changed, &gate)) return 6;
    if (pthread_mutex_unlock(&gate)) return 7;
    if (write(STDOUT_FILENO, "R", 1) != 1) return 8;
    pthread_exit(NULL);
}
"#;
}
