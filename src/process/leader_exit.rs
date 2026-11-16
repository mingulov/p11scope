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
}

impl ExitingTask {
    /// Whether this task can never execute user code again: it is a
    /// zombie or dead, or it is already in `do_exit` (`PF_EXITING` is set
    /// there and never cleared). Both are irreversible. A merely pending
    /// `SIGKILL` does not count: a task running in user mode can execute
    /// a little more user code before the kernel takes the signal.
    fn past_user_mode(self) -> bool {
        matches!(self.stat.state, b'Z' | b'X' | b'x') || self.stat.flags & PF_EXITING != 0
    }
}

trait FinalExitIo {
    type Tasks: Iterator<Item = Result<u32, ()>>;
    fn group_exited(&mut self) -> Result<bool, ()>;
    fn leader(&mut self) -> Result<ExitingTask, ()>;
    fn tasks(&mut self) -> Result<Self::Tasks, ()>;
    /// `Ok(None)` only when the member's directory is provably gone
    /// (`ENOENT`: the thread was released); any other failure is `Err`.
    fn member(&mut self, tid: u32) -> Result<Option<ExitingTask>, ()>;
}

/// Whether the retained thread group is in its final exit: either the
/// original pidfd reports the whole group gone, or the original leader
/// (same birth) and every member listed under it are past user mode.
///
/// A task in that state never runs user code again, so the group can make
/// no further provider call and no further `dlopen`. Thread creation needs
/// a creator that is not yet exiting, and the new thread is linked into
/// the group before `clone` returns to it. A member created during the
/// first listing may be missed by it, but its creator is then read later
/// and was not exiting at creation time; so the task list is read a
/// second time after every member was proven, and any thread it adds
/// fails the proof. An `exec` kill leaves the execing thread live, so it
/// never qualifies. Any unreadable member, a reused leader, or an
/// exhausted budget answers false: only a positive proof counts.
fn final_exit_with<Io: FinalExitIo>(
    io: &mut Io,
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
    let mut seen = std::collections::BTreeSet::new();
    for entry in tasks {
        if !work.spend(2) {
            return false;
        }
        let Ok(tid) = entry else {
            return false;
        };
        seen.insert(tid);
        match io.member(tid) {
            Ok(None) => {}
            Ok(Some(task)) if task.past_user_mode() => {}
            Ok(Some(_)) | Err(()) => return false,
        }
    }
    // A thread the first listing missed was created by a member that was
    // not yet exiting: any such thread fails the proof.
    if !work.spend(1) {
        return false;
    }
    let Ok(again) = io.tasks() else {
        return false;
    };
    for entry in again {
        if !work.spend(1) {
            return false;
        }
        match entry {
            Ok(tid) if seen.contains(&tid) => {}
            _ => return false,
        }
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
    })
}

impl FinalExitIo for OsExitIo<'_> {
    type Tasks =
        std::iter::Map<std::fs::ReadDir, fn(io::Result<std::fs::DirEntry>) -> Result<u32, ()>>;

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
    fn member(&mut self, tid: u32) -> Result<Option<ExitingTask>, ()> {
        let directory = self.directory.directory.as_fd();
        let read = |name: &str, limit| {
            let path = std::ffi::CString::new(format!("task/{tid}/{name}")).map_err(|_| None)?;
            read_relative_io(directory, &path, limit).map_err(|error| {
                (error.kind() == io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::ESRCH))
                .then_some(())
            })
        };
        let stat = match read("stat", STAT_BYTES) {
            Ok(stat) => stat,
            Err(Some(())) => return Ok(None),
            Err(None) => return Err(()),
        };
        parse_exiting_task(&stat).map(Some)
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
        listings: usize,
    }
    impl FinalExitIo for ScriptedFinalExit {
        type Tasks = std::vec::IntoIter<Result<u32, ()>>;
        fn group_exited(&mut self) -> Result<bool, ()> {
            Ok(self.exited)
        }
        fn leader(&mut self) -> Result<ExitingTask, ()> {
            self.leader_reads += 1;
            let mut leader = self.leader;
            if self.reused_leader_after_walk && self.leader_reads > 1 {
                leader.stat.birth += 1;
            }
            Ok(leader)
        }
        fn tasks(&mut self) -> Result<Self::Tasks, ()> {
            self.listings += 1;
            let mut tids = vec![Ok(7)];
            tids.extend(self.members.iter().map(|(tid, _)| Ok(*tid)));
            if self.listings > 1 {
                tids.extend(self.late_member.map(Ok));
            }
            Ok(tids.into_iter())
        }
        fn member(&mut self, tid: u32) -> Result<Option<ExitingTask>, ()> {
            if tid == 7 {
                return Ok(Some(self.leader));
            }
            // A tid recycled between the two listings: the first walk
            // reads the old past member, the closing re-read sees the
            // live new thread under the same tid.
            if self.listings > 1
                && let Some((reused, fresh)) = self.reused_member
                && tid == reused
            {
                return Ok(Some(fresh));
            }
            self.members
                .iter()
                .find(|(member, _)| *member == tid)
                .map(|(_, task)| *task)
                .unwrap_or(Ok(None))
        }
    }
    fn task(state: u8, flags: u32) -> ExitingTask {
        ExitingTask {
            stat: TaskStat {
                birth: 500,
                state,
                flags,
            },
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
            listings: 0,
        }
    }
    fn final_exit(io: &mut ScriptedFinalExit) -> bool {
        final_exit_with(io, 500, &mut LeaderExitReadBudget::for_test(512))
    }
    #[test]
    fn group_past_user_mode_is_in_final_exit() {
        assert!(final_exit(&mut dying_group()));
        let mut single = dying_group();
        single.members.clear();
        single.leader = task(b'R', PF_EXITING);
        assert!(final_exit(&mut single), "a single task already in do_exit");
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
            },
        ));
        assert!(
            !final_exit(&mut reused),
            "a recycled member tid with a live new thread keeps the group unproven"
        );
        assert_eq!(reused.listings, 2, "the task list is read twice");
    }
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
