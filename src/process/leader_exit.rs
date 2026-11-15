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
}
