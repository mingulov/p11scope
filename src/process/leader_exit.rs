//! SPDX-License-Identifier: GPL-3.0-or-later
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
}
