//! SPDX-License-Identifier: GPL-3.0-or-later
//! Actual cold group fixtures: the first view opens after the leader is Z.

use super::*;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

pub(crate) struct ColdLeaderSubject {
    input: ChildStdin,
    output: ChildStdout,
    child: Child,
    pub(crate) program: std::path::PathBuf,
    pub(crate) tids: Vec<u32>,
    pub(crate) table_address: u64,
    pub(crate) callback_address: u64,
    _directory: tempfile::TempDir,
}

impl ColdLeaderSubject {
    pub(crate) fn spawn(workers: u32) -> Self {
        assert!(workers <= 2);
        let directory = tempfile::tempdir().unwrap();
        let program = directory.path().join("cold-leader");
        assert!(
            Command::new("gcc")
                .args([
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-O1",
                    "-pthread",
                    "-rdynamic",
                ])
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/fixtures/cold-leader-view.c"
                ))
                .arg("-o")
                .arg(&program)
                .status()
                .unwrap()
                .success()
        );
        let mut child = Command::new(&program)
            .arg(workers.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        let mut fixture = Self {
            input,
            output,
            child,
            program,
            tids: Vec::new(),
            table_address: 0,
            callback_address: 0,
            _directory: directory,
        };
        let ready = fixture.line();
        let words: Vec<_> = ready.split_whitespace().collect();
        assert_eq!(words[0], "READY");
        assert_eq!(words[1], format!("tgid={}", fixture.pid()));
        assert_eq!(words[2], format!("count={workers}"));
        fixture.table_address =
            u64::from_str_radix(words[5].strip_prefix("table=0x").unwrap(), 16).unwrap();
        fixture.callback_address =
            u64::from_str_radix(words[6].strip_prefix("callback=0x").unwrap(), 16).unwrap();
        fixture.tids = words[3..3 + workers as usize]
            .iter()
            .map(|word| word.split_once('=').unwrap().1.parse().unwrap())
            .collect();
        assert!(fixture.tids.iter().all(|tid| *tid != fixture.pid()));
        fixture
    }

    pub(crate) fn pid(&self) -> u32 {
        self.child.id()
    }

    fn line(&mut self) -> String {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut line = Vec::new();
        loop {
            assert!(Instant::now() < deadline, "fixture line timed out");
            let mut ready = libc::pollfd {
                fd: self.output.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one borrowed pipe fd, one writable pollfd, finite wait.
            let result = unsafe { libc::poll(&mut ready, 1, 50) };
            if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            assert!(result >= 0);
            if result == 0 {
                continue;
            }
            let mut byte = [0];
            self.output.read_exact(&mut byte).unwrap();
            if byte[0] == b'\n' {
                return String::from_utf8(line).unwrap();
            }
            line.push(byte[0]);
            assert!(line.len() <= 256, "fixture line exceeded its fixed bound");
        }
    }

    pub(crate) fn leave_leader(&mut self) {
        self.input.write_all(b"l").unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !process_is_zombie(self.pid()) {
            assert!(Instant::now() < deadline, "leader did not reach Z");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    pub(crate) fn call_three(&mut self) {
        assert!(!self.tids.is_empty());
        self.input.write_all(b"c").unwrap();
        let line = self.line();
        assert!(
            self.tids
                .iter()
                .any(|tid| line == format!("CALLS tid={tid} total=3")),
            "{line}"
        );
    }

    pub(crate) fn exit_one_worker(&mut self) {
        assert_eq!(self.tids.len(), 2);
        self.input.write_all(b"e").unwrap();
        let line = self.line();
        let tid: u32 = line.strip_prefix("EXIT tid=").unwrap().parse().unwrap();
        assert!(self.tids.contains(&tid));
        let path = format!("/proc/{}/task/{tid}", self.pid());
        let deadline = Instant::now() + Duration::from_secs(3);
        while std::fs::metadata(&path).is_ok() {
            assert!(
                Instant::now() < deadline,
                "the commanded worker did not exit"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        self.tids.retain(|member| *member != tid);
    }

    fn exec_worker(&mut self) {
        self.input.write_all(b"x").unwrap();
        let expected = std::fs::metadata("/bin/sleep").unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if std::fs::metadata(format!("/proc/{}/exe", self.pid())).is_ok_and(|actual| {
                (actual.dev(), actual.ino()) == (expected.dev(), expected.ino())
            }) {
                break;
            }
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "worker exec exited early"
            );
            assert!(
                Instant::now() < deadline,
                "worker exec did not become the new image"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn member_namespace(&self) -> MountNamespaceId {
        assert!(!self.tids.is_empty());
        let metadata =
            std::fs::metadata(format!("/proc/{}/task/{}/ns/mnt", self.pid(), self.tids[0],))
                .unwrap();
        MountNamespaceId {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

impl Drop for ColdLeaderSubject {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn warm_group_view_still_opens_before_leader_exit() {
    let mut group = ColdLeaderSubject::spawn(1);
    let view = ProcessView::open(ProcessViewId(31), group.pid()).unwrap();
    assert_eq!(view.mount_namespace(), group.member_namespace());
    group.leave_leader();
    group.call_three();
    assert_eq!(view.pid(), group.pid());
    assert_eq!(view.start_time(), process_start_time(group.pid()).ok());
    assert!(view.still_the_same());
}

#[test]
fn cold_group_view_opens_from_proven_lone_survivor() {
    let mut group = ColdLeaderSubject::spawn(1);
    group.leave_leader();
    let view = ProcessView::open(ProcessViewId(32), group.pid())
        .expect("R56: cold view opens through a proven live group member");
    assert_eq!(view.id(), ProcessViewId(32));
    assert_eq!(view.pid(), group.pid(), "the view remains TGID-owned");
    assert_eq!(view.start_time(), process_start_time(group.pid()).ok());
    assert_eq!(view.mount_namespace(), group.member_namespace());
    assert!(view.still_the_same());
    group.call_three();
}

#[test]
fn cold_group_view_refuses_whole_group_exit() {
    let mut group = ColdLeaderSubject::spawn(0);
    group.leave_leader();
    assert!(ProcessView::open(ProcessViewId(33), group.pid()).is_err());
}

#[test]
fn cold_group_view_opens_shared_filesystem_multiworker_group() {
    let mut group = ColdLeaderSubject::spawn(2);
    group.leave_leader();
    let view = ProcessView::open(ProcessViewId(34), group.pid())
        .expect("matching live worker filesystems provide an unambiguous cold route");
    assert_eq!(view.pid(), group.pid());
    assert_eq!(view.mount_namespace(), group.member_namespace());
    group.call_three();
}

#[test]
fn cold_view_does_not_reuse_a_readable_leader_after_worker_exec() {
    let mut group = ColdLeaderSubject::spawn(2);
    group.leave_leader();
    let view = ProcessView::open(ProcessViewId(35), group.pid()).unwrap();
    group.exec_worker();
    let mut work = CaptureWorkBudget::default();
    assert!(
        view.with_filesystem(&mut work, |_, _| Ok(())).is_err(),
        "a readable successor cannot turn old cold custody into ordinary leader authority"
    );
    let successor = ProcessView::open(ProcessViewId(36), group.pid()).unwrap();
    assert_eq!(successor.pid(), view.pid());
    assert_ne!(successor.id(), view.id());
    successor.with_filesystem(&mut work, |_, _| Ok(())).unwrap();
}

#[test]
fn cold_target_object_and_cached_mountinfo_use_the_same_retained_filesystem() {
    for workers in [1, 2] {
        let mut group = ColdLeaderSubject::spawn(workers);
        group.leave_leader();
        let view = ProcessView::open(ProcessViewId(38), group.pid()).unwrap();
        let mut work = CaptureWorkBudget::default();
        let mut cache = MountTableCache::default();
        for _ in 0..2 {
            let (file, mountinfo) = view
                .open_then_cached_mountinfo(
                    |filesystem| filesystem.open_rooted(&group.program),
                    &mut cache,
                    &mut work,
                )
                .unwrap();
            assert!(!mountinfo.is_empty());
            let metadata = file.metadata().unwrap();
            let expected = group.program.metadata().unwrap();
            assert_eq!(
                (metadata.dev(), metadata.ino()),
                (expected.dev(), expected.ino())
            );
        }
        group.call_three();
    }
}

#[test]
fn cold_constructor_obeys_stopped_and_empty_actual_capture_allowances() {
    use crate::discovery::scan::{CollectionWork, ScanLimits};

    let mut group = ColdLeaderSubject::spawn(1);
    group.leave_leader();
    let mut expired = CaptureWorkBudget::default();
    expired.set_deadline(Some(0));
    let mut cancelled = CaptureWorkBudget::default();
    cancelled.set_collection_work(CollectionWork::new(|_| false));
    let no_bytes = CaptureWorkBudget::new(ScanLimits {
        per_object_bytes: 0,
        total_bytes: 0,
    });
    for mut work in [
        CaptureWorkBudget::with_work_ceiling(0),
        expired,
        cancelled,
        no_bytes,
    ] {
        assert!(ProcessView::open_with_budget(ProcessViewId(40), group.pid(), &mut work).is_err());
        assert_eq!(work.attempted_io_bytes(), 0);
    }
    let mut work = CaptureWorkBudget::default();
    let view = ProcessView::open_with_budget(ProcessViewId(41), group.pid(), &mut work).unwrap();
    assert!(work.attempted_io_bytes() > 0);
    assert_eq!(view.pid(), group.pid());
    group.call_three();
}

#[test]
fn warm_constructor_does_not_bypass_a_stopped_capture() {
    use crate::discovery::scan::CollectionWork;

    let mut group = ColdLeaderSubject::spawn(1);
    let mut expired = CaptureWorkBudget::default();
    expired.set_deadline(Some(0));
    let mut cancelled = CaptureWorkBudget::default();
    cancelled.set_collection_work(CollectionWork::new(|_| false));
    for mut work in [CaptureWorkBudget::with_work_ceiling(0), expired, cancelled] {
        assert!(ProcessView::open_with_budget(ProcessViewId(46), group.pid(), &mut work).is_err());
        assert_eq!(work.attempted_io_bytes(), 0);
    }
    ProcessView::open_with_budget(
        ProcessViewId(47),
        group.pid(),
        &mut CaptureWorkBudget::default(),
    )
    .unwrap();
    group.leave_leader();
    group.call_three();
}

#[test]
fn repeated_cold_constructors_share_one_remaining_collection_allowance() {
    use crate::discovery::scan::CollectionWork;
    use std::sync::atomic::{AtomicU64, Ordering};

    let mut first = ColdLeaderSubject::spawn(1);
    let mut second = ColdLeaderSubject::spawn(1);
    first.leave_leader();
    second.leave_leader();
    let measured = Arc::new(AtomicU64::new(0));
    let seen = measured.clone();
    let mut calibration = CaptureWorkBudget::default();
    calibration.set_collection_work(CollectionWork::new(move |units| {
        seen.fetch_add(units, Ordering::SeqCst);
        true
    }));
    ProcessView::open_with_budget(ProcessViewId(42), first.pid(), &mut calibration).unwrap();
    let one = measured.load(Ordering::SeqCst);
    assert!(one > 0);
    let remaining = Arc::new(AtomicU64::new(one + one / 2));
    let shared = remaining.clone();
    let mut work = CaptureWorkBudget::default();
    work.set_collection_work(CollectionWork::new(move |units| {
        shared
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(units)
            })
            .is_ok()
    }));
    ProcessView::open_with_budget(ProcessViewId(43), first.pid(), &mut work).unwrap();
    let before = work.attempted_io_bytes();
    assert!(ProcessView::open_with_budget(ProcessViewId(44), second.pid(), &mut work).is_err());
    assert!(work.attempted_io_bytes() >= before);
    let stopped = work.attempted_io_bytes();
    assert!(ProcessView::open_with_budget(ProcessViewId(45), first.pid(), &mut work).is_err());
    assert_eq!(
        work.attempted_io_bytes(),
        stopped,
        "a failed shared allowance never renews"
    );
    first.call_three();
    second.call_three();
}
