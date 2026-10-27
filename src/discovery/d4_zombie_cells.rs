//! SPDX-License-Identifier: GPL-3.0-or-later
//! D4 zombie cells: leader-zombie groups with live survivors. Ordinary
//! twins pin the sweep-seam classification (a group without a live member
//! stays exited; a live survivor prepares through retained-member custody
//! without disturbing the shared census; two survivors mint no member);
//! the ignored twin asserts backend parity for collision/data-only zombie
//! mappings on Btrfs.

use super::*;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::time::{Duration, Instant};

/// A thread group whose leader is an unreaped zombie with one live
/// survivor (`spawn`) or two (`spawn_two`). Built with raw syscalls
/// only (fork-safe): the forked child raw-clones each survivor thread
/// into its group on a COW-inherited stack, then the child's main
/// exits its own thread via raw `exit(2)`. Killed and reaped on drop.
/// The survivors share the child's frozen post-fork mappings, so their
/// maps stay byte-stable for like-for-like reads.
struct ZombieLeaderGroup {
    tgid: u32,
    survivor: u32,
    second: Option<u32>,
}

/// The raw-clone survivor: reports its TID over the pipe (whose write end
/// arrives as the argument), then parks in `pause()`. Raw syscalls only.
extern "C" fn clone_survivor_main(arg: *mut std::ffi::c_void) -> libc::c_int {
    let wfd = arg as usize as libc::c_int;
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
    let bytes = tid.to_ne_bytes();
    let mut written = 0;
    while written < bytes.len() {
        // SAFETY: writing the stack bytes to the pipe.
        let done = unsafe {
            libc::write(
                wfd,
                bytes.as_ptr().add(written).cast(),
                bytes.len() - written,
            )
        };
        if done <= 0 {
            unsafe {
                libc::syscall(libc::SYS_exit, 1);
            }
        }
        written += done as usize;
    }
    loop {
        unsafe {
            libc::pause();
        }
    }
}

impl ZombieLeaderGroup {
    fn spawn() -> Self {
        let (tgid, survivors) = Self::spawn_inner(1);
        Self {
            tgid,
            survivor: survivors[0],
            second: None,
        }
    }

    /// A zombie leader with two live survivors: the ambiguous side of
    /// the exactly-one rule, which mints no member.
    fn spawn_two() -> Self {
        let (tgid, survivors) = Self::spawn_inner(2);
        Self {
            tgid,
            survivor: survivors[0],
            second: Some(survivors[1]),
        }
    }

    /// Fork a child that raw-clones `count` (1 or 2) survivors, then
    /// exits its main thread; collect each survivor's reported TID.
    fn spawn_inner(count: usize) -> (u32, Vec<u32>) {
        assert!(count == 1 || count == 2, "one or two survivors");
        let mut stacks = [Box::new([0u8; 65536]), Box::new([0u8; 65536])];
        // Each heap top is 16-aligned (aligned base, multiple-of-16 size).
        let tops = [
            stacks[0].as_mut_ptr_range().end as *mut std::ffi::c_void,
            stacks[1].as_mut_ptr_range().end as *mut std::ffi::c_void,
        ];
        let (mut pipes, mut tid_bytes) = ([0; 2], [0u8; 8]);
        // SAFETY: two valid two-element arrays for pipe2.
        assert_eq!(
            unsafe { libc::pipe2(pipes.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        // SAFETY: the child only makes raw syscalls (close, clone, exit) on
        // the COW-inherited stacks and pipe; no allocator, no pthread, no locks.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            unsafe {
                libc::close(pipes[0]);
                const FLAGS: libc::c_int = libc::CLONE_VM
                    | libc::CLONE_FS
                    | libc::CLONE_FILES
                    | libc::CLONE_SIGHAND
                    | libc::CLONE_THREAD
                    | libc::CLONE_SYSVSEM;
                for top in tops.iter().take(count) {
                    let cloned = libc::clone(
                        clone_survivor_main,
                        *top,
                        FLAGS,
                        pipes[1] as isize as *mut std::ffi::c_void,
                    );
                    if cloned < 0 {
                        libc::_exit(1);
                    }
                }
                // The main thread exits alone; the survivors keep the group.
                libc::syscall(libc::SYS_exit, 0);
                libc::_exit(0);
            }
        }
        // SAFETY: the parent keeps the read end and closes its write copy so
        // a dead child reads as EOF instead of hanging the read below.
        unsafe {
            libc::close(pipes[1]);
        }
        // Each survivor writes its 4-byte TID in one small pipe write,
        // so the bytes split into intact TIDs in either order.
        let want = 4 * count;
        let mut done = 0;
        while done < want {
            // SAFETY: reading into a valid stack buffer.
            let got = unsafe {
                libc::read(
                    pipes[0],
                    tid_bytes.as_mut_ptr().add(done).cast(),
                    want - done,
                )
            };
            assert!(got > 0, "clone survivor never reported its tid");
            done += got as usize;
        }
        // SAFETY: the read end served its single read.
        unsafe {
            libc::close(pipes[0]);
        }
        let survivors = (0..count)
            .map(|index| {
                u32::from_ne_bytes([
                    tid_bytes[4 * index],
                    tid_bytes[4 * index + 1],
                    tid_bytes[4 * index + 2],
                    tid_bytes[4 * index + 3],
                ])
            })
            .collect();
        (pid as u32, survivors)
    }

    /// Live task IDs of the group, sorted.
    fn tasks(&self) -> Vec<u32> {
        let mut tasks: Vec<u32> = std::fs::read_dir(format!("/proc/{}/task", self.tgid))
            .expect("task lists")
            .map(|entry| {
                entry
                    .expect("entry reads")
                    .file_name()
                    .to_string_lossy()
                    .parse()
                    .expect("numeric task id")
            })
            .collect();
        tasks.sort();
        tasks
    }
}

impl Drop for ZombieLeaderGroup {
    fn drop(&mut self) {
        unsafe {
            // SIGKILL to the TGID stops the survivor; the leader is dead.
            libc::kill(self.tgid as libc::pid_t, libc::SIGKILL);
            let mut status = 0;
            while libc::waitpid(self.tgid as libc::pid_t, &mut status, 0) < 0 {
                let err = std::io::Error::last_os_error().raw_os_error();
                if err == Some(libc::ECHILD) {
                    break;
                }
                assert_eq!(err, Some(libc::EINTR));
            }
        }
    }
}

/// Wait until `tgid` reads as a zombie leader.
fn wait_leader_zombie(tgid: u32) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !crate::process::process_is_zombie(tgid) {
        assert!(
            Instant::now() < deadline,
            "leader {tgid} never reached zombie state"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// The group holds exactly one live survivor: the survivor is listed and
/// every other task entry (if any) is the zombie leader itself, whose
/// listing is kernel-dependent.
fn assert_lone_survivor(group: &ZombieLeaderGroup) {
    assert_ne!(group.survivor, group.tgid, "survivor is a nonleader");
    let tasks = group.tasks();
    assert!(
        tasks.contains(&group.survivor),
        "survivor {} listed in {tasks:?}",
        group.survivor
    );
    for task in &tasks {
        assert!(
            *task == group.survivor || *task == group.tgid,
            "unexpected task {task} in {tasks:?}"
        );
    }
}

/// The group holds exactly two live survivors: both are listed and
/// every other task entry (if any) is the zombie leader itself, whose
/// listing is kernel-dependent.
fn assert_two_survivors(group: &ZombieLeaderGroup) {
    let second = group.second.expect("a two-survivor group");
    assert_ne!(group.survivor, group.tgid, "first survivor is a nonleader");
    assert_ne!(second, group.tgid, "second survivor is a nonleader");
    assert_ne!(
        group.survivor, second,
        "the two survivors are distinct tasks"
    );
    let tasks = group.tasks();
    assert!(
        tasks.contains(&group.survivor),
        "first survivor {} listed in {tasks:?}",
        group.survivor
    );
    assert!(
        tasks.contains(&second),
        "second survivor {second} listed in {tasks:?}"
    );
    for task in &tasks {
        assert!(
            *task == group.survivor || *task == second || *task == group.tgid,
            "unexpected task {task} in {tasks:?}"
        );
    }
}

#[test]
fn zombie_group_without_live_member_is_exited_at_sweep_seam() {
    // Control first: a live process prepares at this seam (and never
    // mints a member), so the exited verdict below discriminates.
    let mut live = std::process::Command::new("sleep")
        .arg("30")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("sleep spawns");
    let mut io = OsConfirmIo::default();
    let mut budget = CaptureWorkBudget::default();
    let prepared = prepare_confirmation(&mut io, live.id(), &BTreeSet::new(), &mut budget, None);
    let prepared = prepared.expect("live control prepares at the seam");
    assert!(
        prepared.member.is_none(),
        "live leaders never mint a member"
    );
    drop(prepared);
    live.kill().expect("live control dies");
    let _ = live.wait();
    // Then the zombie: killed and deliberately unreaped, so no member
    // can validate for it.
    let mut dead = std::process::Command::new("sleep")
        .arg("30")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("sleep spawns");
    let pid = dead.id();
    dead.kill().expect("victim dies");
    wait_leader_zombie(pid);
    let mut io = OsConfirmIo::default();
    let mut budget = CaptureWorkBudget::default();
    let out = prepare_confirmation(&mut io, pid, &BTreeSet::new(), &mut budget, None);
    assert!(
        matches!(out, Err(Confirmation::Exited)),
        "a zombie group without a live member stays exited at the seam"
    );
    let _ = dead.wait();
}

#[test]
fn zombie_group_with_live_survivor_prepares_through_member() {
    let group = ZombieLeaderGroup::spawn();
    wait_leader_zombie(group.tgid);
    assert_lone_survivor(&group);
    let mut io = OsConfirmIo::default();
    let mut budget = CaptureWorkBudget::default();
    let prepared = prepare_confirmation(&mut io, group.tgid, &BTreeSet::new(), &mut budget, None)
        .expect("a zombie group with a live survivor prepares");
    let member = prepared
        .member
        .as_ref()
        .expect("prepare carries the survivor member");
    let selector = member.selector().expect("carried member selects");
    assert_eq!(selector.tgid(), group.tgid);
    assert_eq!(selector.tid(), group.survivor);
    assert!(
        !prepared.entries.is_empty(),
        "survivor maps, not empty leader maps"
    );
    // Like-for-like: the prepared entries equal an independent read of
    // the survivor's maps (the frozen post-fork mm reads identically).
    let file = std::fs::File::open(format!("/proc/{}/task/{}/maps", group.tgid, group.survivor))
        .expect("survivor maps open");
    let mut reread_budget = CaptureWorkBudget::default();
    let expect = crate::discovery::scan::read_maps_or_refuse(
        file,
        &mut reread_budget,
        crate::attach::monotonic_ns,
    )
    .expect("survivor maps read");
    assert_eq!(prepared.entries, expect);
    // The member exe is the same group image: the fixture never execs,
    // so it equals this live process's own exe identity. (The zombie
    // leader's own exe link is unreadable; only the survivor serves it.)
    assert_eq!(
        member.read_exe_identity().expect("member exe reads"),
        crate::discovery::caller_registry::read_exe_identity(std::process::id())
            .expect("self exe reads")
    );
}

/// The member's original is the confirm pin's own pidfd (duplicated),
/// never a fresh numeric reopen: both fds name the same open file
/// description (`kcmp KCMP_FILE`). A numeric reopen would name the same
/// process through a different description — and the wrong process
/// after a pid recycle.
#[test]
fn member_original_is_the_confirm_pin_not_a_numeric_reopen() {
    let group = ZombieLeaderGroup::spawn();
    wait_leader_zombie(group.tgid);
    assert_lone_survivor(&group);
    let mut io = OsConfirmIo::default();
    let mut budget = CaptureWorkBudget::default();
    let prepared = prepare_confirmation(&mut io, group.tgid, &BTreeSet::new(), &mut budget, None)
        .expect("a zombie group with a live survivor prepares");
    assert!(
        prepared.member.is_some(),
        "prepare carries the survivor member"
    );
    let minter = io.minter.as_ref().expect("mint stashes its original");
    let confirm = prepared.pin.pin.pidfd().expect("confirm pin has a pidfd");
    let original = minter.pin.pidfd().expect("original has a pidfd");
    assert!(
        same_open_file_description(confirm, original),
        "the member original is the confirm pin's own pidfd, not a numeric reopen"
    );
}

/// Whether two fds of this process name the same open file description.
/// `kcmp` has no libc wrapper on Linux, so this issues the raw syscall
/// (`KCMP_FILE`); same-process comparison needs no privilege. A broken
/// probe fails the twin rather than passing vacuously.
fn same_open_file_description(first: BorrowedFd<'_>, second: BorrowedFd<'_>) -> bool {
    const KCMP_FILE: libc::c_long = 0;
    let pid = std::process::id() as libc::c_long;
    // SAFETY: a pure comparison of two owned fds; sends nothing.
    let compared = unsafe {
        libc::syscall(
            libc::SYS_kcmp,
            pid,
            pid,
            KCMP_FILE,
            first.as_raw_fd() as libc::c_long,
            second.as_raw_fd() as libc::c_long,
        )
    };
    if compared != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        assert_eq!(errno, 0, "the kcmp probe itself failed");
        return false;
    }
    true
}

#[test]
fn zombie_group_with_two_live_survivors_stays_exited_at_sweep_seam() {
    let group = ZombieLeaderGroup::spawn_two();
    wait_leader_zombie(group.tgid);
    assert_two_survivors(&group);
    let mut io = OsConfirmIo::default();
    let mut budget = CaptureWorkBudget::default();
    let out = prepare_confirmation(&mut io, group.tgid, &BTreeSet::new(), &mut budget, None);
    assert!(
        matches!(out, Err(Confirmation::Exited)),
        "a zombie group with two live survivors mints no member and stays exited at the seam"
    );
}

#[test]
fn member_confirm_leaves_shared_census_quiescent() {
    let group = ZombieLeaderGroup::spawn();
    wait_leader_zombie(group.tgid);
    assert_lone_survivor(&group);
    let policy = SegmentPolicy::try_snapshot(1, 1).expect("actual FD census");
    let owner = ReservationOwner::new(policy);
    let resources = owner.batch();
    let mut io = OsConfirmIo::default();
    let mut budget = CaptureWorkBudget::default();
    let prepared = prepare_confirmation(
        &mut io,
        group.tgid,
        &BTreeSet::new(),
        &mut budget,
        Some(&resources),
    )
    .expect("member confirm prepares");
    assert!(
        prepared.member.is_some(),
        "shared-owner confirm carries the member"
    );
    // The census boundary refuses while the confirm holds its pin.
    assert!(
        owner.reconcile(policy).is_err(),
        "a live confirm blocks the census"
    );
    drop(prepared);
    assert_eq!(
        owner.state_for_test().0,
        [0; 4],
        "a dropped member leaves no shared lease"
    );
    // ... and passes once the member dropped before the boundary.
    owner
        .reconcile(policy)
        .expect("census passes after the member dropped");
}

/// A zombie-leader group whose shared mm holds one mapping of `path` (at
/// a child-chosen address): the forked child opens and maps the file,
/// reports the address, raw-clones a survivor, then exits its leader
/// thread. Only async-signal-safe calls run post-fork. Killed and reaped
/// on drop.
struct ZombieMapperGroup {
    tgid: u32,
    survivor: u32,
    address: u64,
}

impl ZombieMapperGroup {
    fn spawn(path: &std::path::Path, exec: bool) -> Self {
        let c_path =
            std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("path encodes");
        let mut stack = Box::new([0u8; 65536]);
        let stack_top = stack.as_mut_ptr_range().end as *mut std::ffi::c_void;
        // Eight address bytes from the child, then four tid bytes from the
        // survivor (whose write end stays open, so read exactly this many).
        let (mut pipes, mut report) = ([0; 2], [0u8; 12]);
        // SAFETY: two valid two-element arrays for pipe2.
        assert_eq!(
            unsafe { libc::pipe2(pipes.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        // SAFETY: the child only calls open/fstat/mmap/write/close/clone
        // and exit on COW memory; no allocator, no pthread, no locks.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            unsafe {
                libc::close(pipes[0]);
                // SAFETY: read-only open of the NUL-terminated fixture path.
                let fd = libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
                if fd < 0 {
                    libc::_exit(11);
                }
                let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
                if libc::fstat(fd, stat.as_mut_ptr()) != 0 {
                    libc::_exit(12);
                }
                // SAFETY: fstat initialized the output.
                let len = stat.assume_init().st_size.max(4096) as usize;
                let prot = if exec {
                    libc::PROT_READ | libc::PROT_EXEC
                } else {
                    libc::PROT_READ
                };
                // SAFETY: a private file mapping of the held fixture bytes.
                let at = libc::mmap(
                    std::ptr::null_mut(),
                    len.min(4096),
                    prot,
                    libc::MAP_PRIVATE,
                    fd,
                    0,
                );
                libc::close(fd);
                if at == libc::MAP_FAILED {
                    libc::_exit(13);
                }
                let addr = at as u64;
                if libc::write(
                    pipes[1],
                    std::ptr::from_ref(&addr).cast(),
                    std::mem::size_of::<u64>(),
                ) != std::mem::size_of::<u64>() as isize
                {
                    libc::_exit(14);
                }
                const FLAGS: libc::c_int = libc::CLONE_VM
                    | libc::CLONE_FS
                    | libc::CLONE_FILES
                    | libc::CLONE_SIGHAND
                    | libc::CLONE_THREAD
                    | libc::CLONE_SYSVSEM;
                let cloned = libc::clone(
                    clone_survivor_main,
                    stack_top,
                    FLAGS,
                    pipes[1] as isize as *mut std::ffi::c_void,
                );
                if cloned < 0 {
                    libc::_exit(15);
                }
                // The main thread exits alone; the survivor keeps the group.
                libc::syscall(libc::SYS_exit, 0);
                libc::_exit(0);
            }
        }
        // SAFETY: the parent keeps the read end and closes its write copy.
        unsafe {
            libc::close(pipes[1]);
        }
        let mut done = 0;
        while done < report.len() {
            // SAFETY: reading into a valid stack buffer.
            let got = unsafe {
                libc::read(
                    pipes[0],
                    report.as_mut_ptr().add(done).cast(),
                    report.len() - done,
                )
            };
            assert!(got > 0, "mapper child never reported address+tid");
            done += got as usize;
        }
        // SAFETY: the read end served its single report.
        unsafe {
            libc::close(pipes[0]);
        }
        let address = u64::from_ne_bytes(report[0..8].try_into().expect("address bytes"));
        let survivor = u32::from_ne_bytes(report[8..12].try_into().expect("tid bytes"));
        assert_ne!(address, 0, "mapped address is real");
        assert_ne!(survivor, 0, "survivor tid is real");
        Self {
            tgid: pid as u32,
            survivor,
            address,
        }
    }

    /// Live task IDs of the group, sorted.
    fn tasks(&self) -> Vec<u32> {
        let mut tasks: Vec<u32> = std::fs::read_dir(format!("/proc/{}/task", self.tgid))
            .expect("task lists")
            .map(|entry| {
                entry
                    .expect("entry reads")
                    .file_name()
                    .to_string_lossy()
                    .parse()
                    .expect("numeric task id")
            })
            .collect();
        tasks.sort();
        tasks
    }

    /// The survivor's maps through the production maps reader.
    fn maps(&self) -> Vec<MapEntry> {
        let file = std::fs::File::open(format!("/proc/{}/task/{}/maps", self.tgid, self.survivor))
            .expect("survivor maps open");
        crate::discovery::scan::read_maps_or_refuse(
            file,
            &mut CaptureWorkBudget::default(),
            crate::attach::monotonic_ns,
        )
        .expect("survivor maps read")
    }
}

impl Drop for ZombieMapperGroup {
    fn drop(&mut self) {
        unsafe {
            // SIGKILL to the TGID stops the survivor; the leader is dead.
            libc::kill(self.tgid as libc::pid_t, libc::SIGKILL);
            let mut status = 0;
            while libc::waitpid(self.tgid as libc::pid_t, &mut status, 0) < 0 {
                let err = std::io::Error::last_os_error().raw_os_error();
                if err == Some(libc::ECHILD) {
                    break;
                }
                assert_eq!(err, Some(libc::EINTR));
            }
        }
    }
}

fn assert_mapper_lone_survivor(group: &ZombieMapperGroup) {
    assert_ne!(group.survivor, group.tgid, "survivor is a nonleader");
    let tasks = group.tasks();
    assert!(
        tasks.contains(&group.survivor),
        "survivor {} listed in {tasks:?}",
        group.survivor
    );
    for task in &tasks {
        assert!(
            *task == group.survivor || *task == group.tgid,
            "unexpected task {task} in {tasks:?}"
        );
    }
}

/// Userspace attribution of one zombie TGID through the production
/// probe. Mirrors `attribute_child` for pids without a `SwapChild`.
fn d4_zombie_attribute_pid(
    pid: u32,
    snapshot: Vec<MapEntry>,
    index: &KnownKeyIndex,
) -> SweepAttribution {
    attribute_unselected(
        &[(pid, snapshot)],
        &BTreeSet::new(),
        &BTreeSet::new(),
        index,
        &mut OsMemberProbe::default(),
        &mut CaptureWorkBudget::default(),
    )
}

/// Kernel attribution of one zombie TGID: a fresh generation with
/// validated slots, zero fallback and zero userspace reads. Mirrors
/// `d4_kernel_collision_attribution`, which is bound to `SwapChild`.
#[allow(clippy::too_many_arguments)]
fn d4_zombie_kernel_attribution_for_pid(
    pid: u32,
    snapshot: Vec<MapEntry>,
    pins: &crate::discovery::identity::PinnedObjects,
    object: PinnedObjectId,
    key: ObjectKey,
    session: &mut crate::discovery::kernel_identity::IdentitySession,
    generation: u64,
) -> SweepAttribution {
    use crate::discovery::kernel_identity::{AnchorPass, ExaminedCustody, KernelMemberProbe};
    use std::sync::{Arc, Mutex};

    let (mut index, refused) = KnownKeyIndex::build(
        [(key, Some(object))],
        &BTreeMap::from([(key, object)]),
        [],
        pins,
    );
    assert!(refused.is_empty(), "{refused:?}");
    assert!(
        index.map_files_keys().contains(&key),
        "Btrfs collision must require actual per-range proof"
    );
    let owner = ReservationOwner::for_examined(
        SegmentPolicy::try_snapshot(0, 0).expect("actual FD census"),
        0,
    );
    let mut custody = ExaminedCustody::new(owner, BTreeMap::new());
    custody
        .reconcile(SegmentPolicy::try_snapshot(1, 1).expect("actual confirmation FD census"))
        .expect("shared physical reservation owner");
    let pass = AnchorPass::prepare(pins, [(key, object)], custody);
    assert!(pass.fallback.is_empty(), "{:?}", pass.fallback);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut installed = session
        .install_anchors(pass, generation, deadline)
        .expect("install actual held-file anchors");
    let trace = Arc::new(Mutex::new(ProofTrace::default()));
    let out = {
        let mut probe = KernelMemberProbe::new(
            &mut installed,
            OsConfirmIo::with_pool(None).observing(trace.clone()),
            deadline,
        );
        probe
            .install_expectations(&mut index)
            .expect("actual validated anchor expectations");
        assert!(
            index
                .match_slots
                .get(&key)
                .is_some_and(|slots| !slots.is_empty()),
            "the held provider has no validated actual kernel slot"
        );
        let mut budget = CaptureWorkBudget::default();
        assert!(
            !budget.has_collection_work(),
            "exercise actual kernel proof, not scoped fallback"
        );
        attribute_unselected(
            &[(pid, snapshot)],
            &BTreeSet::new(),
            &BTreeSet::new(),
            &index,
            &mut probe,
            &mut budget,
        )
    };
    drop(installed);
    let fallback = session.fallback_totals();
    assert_eq!(fallback.passes, 0, "{fallback:?}");
    assert_eq!(fallback.pids, 0, "{fallback:?}");
    assert_eq!(fallback.keys, 0, "{fallback:?}");
    assert!(fallback.first_reason.is_none(), "{fallback:?}");
    assert!(
        trace.lock().unwrap().reads.is_empty(),
        "the required kernel leg performed userspace range-proof reads"
    );
    out
}

/// Zombie-leader collision parity plus the data-only twin: three
/// leader-zombie groups (one mapping the held file executably, one
/// mapping the distinct equal-byte colliding file executably, one
/// mapping the held file data-only), each with exactly one live
/// survivor. Both backends must agree: edge / named mismatch / unsettled
/// data with zero proof demand, on fresh generations without fallback.
#[test]
#[ignore = "root Btrfs disk TMPDIR plus eligible BTF/task_vma identity; zombie survivor collision parity"]
fn privileged_d4_btrfs_zombie_leader_collision_and_dataonly_twins() {
    use crate::discovery::identity::{PinnedObjects, test_fixture::real_scan_pin};
    use crate::discovery::kernel_identity::IdentitySession;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::MetadataExt as _;

    crate::attach::identity_iter::ensure_kernel_identity_btf()
        .expect("required kernel identity capability; refusal cannot qualify");
    let btf = aya::Btf::from_sys_fs().expect("readable host BTF");
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path();
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    let c_parent = std::ffi::CString::new(parent.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a valid path and writable statfs buffer, read only on success.
    assert_eq!(
        unsafe { libc::statfs(c_parent.as_ptr(), stat.as_mut_ptr()) },
        0
    );
    // SAFETY: initialized by the successful statfs above.
    // `f_type` is signed on glibc and unsigned on musl; the magic fits both.
    #[allow(clippy::unnecessary_cast)]
    let magic = unsafe { stat.assume_init().f_type } as u64 & 0xffff_ffff;
    assert_eq!(magic, 0x9123_683e, "actual fixture TMPDIR must be Btrfs");
    create_subvolume(parent, "a");
    create_subvolume(parent, "b");
    let a_path = parent.join("a/libzombie.so");
    let b_path = parent.join("b/libzombie.so");
    std::fs::write(&a_path, vec![0x5cu8; 8192]).unwrap();
    std::fs::copy(&a_path, &b_path).unwrap();
    let a_file = std::fs::File::open(&a_path).unwrap();
    let b_file = std::fs::File::open(&b_path).unwrap();
    let a = a_file.metadata().unwrap();
    let b = b_file.metadata().unwrap();
    assert_eq!(
        std::fs::read(&a_path).unwrap(),
        std::fs::read(&b_path).unwrap()
    );
    assert_eq!(
        a.ino(),
        b.ino(),
        "fresh subvolume files share the inode number"
    );
    assert_ne!(
        (a.dev(), a.ino()),
        (b.dev(), b.ino()),
        "full physical IDs must differ"
    );

    let group_a = ZombieMapperGroup::spawn(&a_path, true);
    let group_b = ZombieMapperGroup::spawn(&b_path, true);
    let group_data = ZombieMapperGroup::spawn(&a_path, false);
    for group in [&group_a, &group_b, &group_data] {
        wait_leader_zombie(group.tgid);
        assert_mapper_lone_survivor(group);
    }
    let snapshots = [group_a.maps(), group_b.maps(), group_data.maps()];
    fn line_at(snapshot: &[MapEntry], address: u64) -> &MapEntry {
        snapshot
            .iter()
            .find(|entry| entry.start == address)
            .expect("independent live mapping")
    }
    let a_text = line_at(&snapshots[0], group_a.address);
    let b_text = line_at(&snapshots[1], group_b.address);
    let a_data = line_at(&snapshots[2], group_data.address);
    assert_eq!(a_text.permissions, *b"r-xp");
    assert_eq!(b_text.permissions, *b"r-xp");
    assert_eq!(a_data.permissions, *b"r--p");
    let key = ObjectKey::of(a_text);
    for entry in [b_text, a_data] {
        assert_eq!(
            ObjectKey::of(entry),
            key,
            "actual lexical collision, not scripted keys"
        );
    }
    let digest = p11scope_manifest::identity::hex(&Sha256::digest(std::fs::read(&a_path).unwrap()));
    let pins: PinnedObjects = real_scan_pin(&a_path, Some(key), 0, &digest);
    let object = pins.pinned().next().expect("actual held-file pin").id;
    let (userspace_index, refused) = KnownKeyIndex::build(
        [(key, Some(object))],
        &BTreeMap::from([(key, object)]),
        [],
        &pins,
    );
    assert!(refused.is_empty(), "{refused:?}");
    assert!(userspace_index.map_files_keys().contains(&key));
    let probe_dir = tempfile::tempdir().unwrap();
    let mut session = IdentitySession::probe_and_load(&btf, probe_dir.path())
        .expect("actual strict-loaded kernel session; no refused/fallback positive");
    for (position, group) in [&group_a, &group_b, &group_data].into_iter().enumerate() {
        let userspace =
            d4_zombie_attribute_pid(group.tgid, snapshots[position].clone(), &userspace_index);
        let kernel = d4_zombie_kernel_attribution_for_pid(
            group.tgid,
            snapshots[position].clone(),
            &pins,
            object,
            key,
            &mut session,
            position as u64 + 1,
        );
        assert_eq!(
            userspace.members, kernel.members,
            "exact same-population backend members"
        );
        assert_eq!(
            userspace.losses, kernel.losses,
            "same actual loss classifications"
        );
        for (backend, out) in [("userspace", userspace), ("kernel", kernel)] {
            let members: Vec<_> = out.members.iter().map(|member| member.pid).collect();
            match position {
                0 => {
                    assert_eq!(members, [group.tgid], "{backend} exact zombie caller");
                    assert_eq!(
                        out.members[0]
                            .objects
                            .iter()
                            .map(|matched| (matched.key, matched.object))
                            .collect::<Vec<_>>(),
                        [(key, object)],
                        "{backend} exact held original-provider edge"
                    );
                    assert!(out.losses.is_empty(), "{backend}: {:?}", out.member_losses);
                    assert_eq!(out.probed, 1, "{backend} nonempty executable proof demand");
                }
                1 => {
                    assert!(
                        members.is_empty(),
                        "{backend} attributed the distinct equal-byte file"
                    );
                    assert_eq!(
                        out.losses,
                        BTreeMap::from([(AttributionLoss::IdentityMismatch, 1)])
                    );
                    assert_eq!(out.probed, 1, "{backend} real negative proof demand");
                }
                2 => {
                    assert!(
                        members.is_empty(),
                        "{backend} attributed a data-only mapping"
                    );
                    assert!(out.losses.is_empty(), "{backend}: {:?}", out.member_losses);
                    assert_eq!(
                        out.probed, 0,
                        "{backend} data-only input costs no executable proof"
                    );
                }
                _ => unreachable!(),
            }
        }
        assert_mapper_lone_survivor(group);
    }
    eprintln!(
        "D4_ZOMBIE_COLLISION groups={}/{}/{} userspace=1/0/0 kernel=1/0/0 \
         equal_bytes=true lexical_collision=true fallback=none",
        group_a.tgid, group_b.tgid, group_data.tgid
    );
    drop((group_a, group_b, group_data));
    drop((session, pins, a_file, b_file));
    std::fs::remove_file(&a_path).unwrap();
    std::fs::remove_file(&b_path).unwrap();
    std::fs::remove_dir(parent.join("a")).unwrap();
    std::fs::remove_dir(parent.join("b")).unwrap();
}

/// ESRCH text the real kernel returns for a zombie-leader `map_files`
/// stat (privileged open succeeds, `fstatat` fails ESRCH); see
/// `evidence/r4/zombie2-userspace.strace`.
fn zombie_leader_esrch() -> String {
    std::io::Error::from_raw_os_error(libc::ESRCH).to_string()
}

/// The fixture confirm pin: the real open result, so the mint derives
/// its original from the confirm pin like production (never a numeric
/// reopen). `open` stays infallible; the mint propagates a stored error.
struct ZombieProofPin {
    pin: Result<std::sync::Arc<crate::process::PidPin>, String>,
}

/// `ConfirmIo` whose leader-path range reads fail exactly like the real
/// kernel for a zombie leader (ESRCH) and whose member-path reads
/// succeed with the canned per-inode identity. Mint acquires the real
/// survivor, so routing (stash vs leader) is what the tests pin.
struct ZombieProofIo {
    entries: Vec<MapEntry>,
    survivor: u32,
    member_owner: ReservationOwner,
    stashed: Option<crate::discovery::retained_member::RetainedGroupMember>,
    minter: Option<ReservedPin<std::sync::Arc<crate::process::PidPin>>>,
    member_reads: std::rc::Rc<std::cell::RefCell<Vec<(u64, u64)>>>,
    leader_reads: std::rc::Rc<std::cell::RefCell<Vec<(u64, u64)>>>,
}

impl ZombieProofIo {
    fn canned(
        entries: Vec<MapEntry>,
        survivor: u32,
        member_reads: std::rc::Rc<std::cell::RefCell<Vec<(u64, u64)>>>,
        leader_reads: std::rc::Rc<std::cell::RefCell<Vec<(u64, u64)>>>,
    ) -> Self {
        Self {
            entries,
            survivor,
            // Two retained slots, like the production member owner: the
            // member directory plus the dup'd original pidfd.
            member_owner: ReservationOwner::new(SegmentPolicy::from_headroom(64, 1, 2)),
            stashed: None,
            minter: None,
            member_reads,
            leader_reads,
        }
    }

    fn identity_for(&self, start: u64, end: u64) -> FileIdentity {
        self.entries
            .iter()
            .find(|entry| (entry.start, entry.end) == (start, end))
            .map(|entry| super::vm_file(entry.inode))
            .unwrap_or_else(|| super::vm_file(super::PROVIDER))
    }
}

impl ConfirmIo for ZombieProofIo {
    type Pin = ZombieProofPin;

    fn open(&mut self, pid: u32) -> Result<Self::Pin, String> {
        Ok(ZombieProofPin {
            pin: crate::process::PidPin::open(pid).map(std::sync::Arc::new),
        })
    }

    fn start_time(&self, _: &Self::Pin) -> Option<u64> {
        Some(4_242)
    }

    fn still_the_same(&self, _: &Self::Pin) -> bool {
        true
    }

    fn exe(&self, _: u32) -> Option<ExeIdentity> {
        if let Some(member) = &self.stashed {
            return member.read_exe_identity();
        }
        Some(super::exe())
    }

    fn maps(&mut self, _: u32, _: &mut CaptureWorkBudget) -> Result<Vec<MapEntry>, String> {
        Ok(self.entries.clone())
    }

    fn gone(&self, pid: u32) -> bool {
        if self
            .stashed
            .as_ref()
            .is_some_and(|member| member.selector().is_ok())
        {
            return false;
        }
        crate::process::process_is_zombie(pid)
    }

    fn mapped_file(&mut self, _: u32, start: u64, end: u64) -> Result<FileIdentity, String> {
        if self.stashed.is_some() {
            self.member_reads.borrow_mut().push((start, end));
            Ok(self.identity_for(start, end))
        } else {
            self.leader_reads.borrow_mut().push((start, end));
            Err(zombie_leader_esrch())
        }
    }

    fn mint_member(
        &mut self,
        pid: u32,
        pin: &Self::Pin,
        budget: &mut CaptureWorkBudget,
    ) -> Result<(), Confirmation> {
        use crate::discovery::retained_member::RetainedGroupMember;
        self.stashed = None;
        self.minter = None;
        if !crate::process::process_is_zombie(pid) {
            return Ok(());
        }
        // The original derives from the confirm pin (duplicated), never
        // a numeric reopen; its lease is reserved before the dup, like
        // production.
        let held = pin
            .pin
            .clone()
            .map_err(|error| Confirmation::Lost(AttributionLoss::MapFilesUnavailable, error))?;
        let lease = self
            .member_owner
            .batch()
            .pin()
            .map_err(|error| Confirmation::Lost(AttributionLoss::MapFilesUnavailable, error))?;
        let original =
            std::sync::Arc::new(held.try_clone().map_err(|error| {
                Confirmation::Lost(AttributionLoss::MapFilesUnavailable, error)
            })?);
        let deadline = Instant::now() + Duration::from_secs(10);
        match RetainedGroupMember::acquire(
            &original,
            self.survivor,
            &self.member_owner,
            budget,
            deadline,
        ) {
            Ok(member) => {
                self.stashed = Some(member);
                self.minter = Some(ReservedPin {
                    pin: original,
                    _lease: Some(lease),
                });
                Ok(())
            }
            Err(_) => Ok(()),
        }
    }

    fn take_member(&mut self) -> Option<crate::discovery::retained_member::RetainedGroupMember> {
        self.stashed.take()
    }

    fn return_member(
        &mut self,
        _pid: u32,
        member: Option<crate::discovery::retained_member::RetainedGroupMember>,
    ) {
        self.stashed = member;
    }
}

struct ZombieProofProbe {
    entries: Vec<MapEntry>,
    survivor: u32,
    member_reads: std::rc::Rc<std::cell::RefCell<Vec<(u64, u64)>>>,
    leader_reads: std::rc::Rc<std::cell::RefCell<Vec<(u64, u64)>>>,
}

impl MemberProbe for ZombieProofProbe {
    fn confirm(
        &mut self,
        pid: u32,
        prove: &BTreeSet<ObjectKey>,
        budget: &mut CaptureWorkBudget,
    ) -> Confirmation {
        let mut io = ZombieProofIo::canned(
            self.entries.clone(),
            self.survivor,
            self.member_reads.clone(),
            self.leader_reads.clone(),
        );
        confirm_with_resources(&mut io, pid, prove, budget, None)
    }

    fn stat_ranges(
        &mut self,
        _: u32,
        _: &[(u64, u64)],
        _: &mut CaptureWorkBudget,
    ) -> MappedIdentities {
        MappedIdentities::new()
    }
}

#[test]
fn zombie_survivor_confirm_routes_range_proofs_through_member() {
    // Custody first: prepare must carry the survivor, so a later
    // attribution failure pins routing, not minting.
    let group = ZombieLeaderGroup::spawn();
    wait_leader_zombie(group.tgid);
    assert_lone_survivor(&group);
    let member_reads = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let leader_reads = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let mut io = ZombieProofIo::canned(
        super::provider_caller(),
        group.survivor,
        member_reads.clone(),
        leader_reads.clone(),
    );
    let mut budget = CaptureWorkBudget::default();
    let prepared = prepare_confirmation(
        &mut io,
        group.tgid,
        &BTreeSet::from([super::key(super::PROVIDER)]),
        &mut budget,
        None,
    )
    .expect("member confirm prepares");
    let selector = prepared
        .member
        .as_ref()
        .expect("prepare carries the survivor")
        .selector()
        .expect("carried member selects");
    assert_eq!(selector.tgid(), group.tgid);
    assert_eq!(selector.tid(), group.survivor);
    drop(prepared);
    drop(io);
    // Then attribution: leader-path reads fail ESRCH like the real
    // kernel, member-path reads succeed, so the group attributes with
    // its held object only when proofs route through the member.
    let checks = super::Checks::default();
    let index = super::provider_index(&checks);
    let member_reads = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let leader_reads = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let mut probe = ZombieProofProbe {
        entries: super::provider_caller(),
        survivor: group.survivor,
        member_reads: member_reads.clone(),
        leader_reads: leader_reads.clone(),
    };
    let mut budget = CaptureWorkBudget::default();
    let out = attribute_unselected(
        &[(group.tgid, super::provider_caller())],
        &BTreeSet::new(),
        &BTreeSet::new(),
        &index,
        &mut probe,
        &mut budget,
    );
    assert_eq!(
        out.members.len(),
        1,
        "zombie survivor attributes through member proofs: {out:?}"
    );
    assert_eq!(out.members[0].pid, group.tgid);
    assert_eq!(out.members[0].objects.len(), 1);
    assert_eq!(out.members[0].objects[0].key, super::key(super::PROVIDER));
    assert_eq!(out.members[0].objects[0].object, super::OBJECT);
    assert!(out.losses.is_empty(), "{:?}", out.member_losses);
    assert_eq!(out.probed, 1);
    assert!(
        !member_reads.borrow().is_empty(),
        "member reads served the proofs"
    );
    assert!(
        leader_reads.borrow().is_empty(),
        "no leader-path range reads: {:?}",
        leader_reads.borrow()
    );
}

struct ZombieUserspaceHook;

impl crate::discovery::confirm_shards::SegmentProof for ZombieUserspaceHook {
    fn prove<'r>(
        &'r mut self,
        _batch: &crate::discovery::confirm_shards::AcceptedBatch<'_>,
        _budget: &mut CaptureWorkBudget,
        _resources: &IoResources,
    ) -> crate::discovery::kernel_identity::ProofDecision<'r> {
        crate::discovery::kernel_identity::ProofDecision::Userspace(
            crate::discovery::kernel_identity::RunFailure::AttachOrRead,
        )
    }
}

#[test]
fn zombie_survivor_segment_fallback_routes_range_proofs_through_member() {
    let group = ZombieLeaderGroup::spawn();
    wait_leader_zombie(group.tgid);
    assert_lone_survivor(&group);
    let member_reads = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let leader_reads = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let mut io = ZombieProofIo::canned(
        super::provider_caller(),
        group.survivor,
        member_reads.clone(),
        leader_reads.clone(),
    );
    let policy = SegmentPolicy::from_headroom(16, 1, 1);
    let owner = ReservationOwner::new(policy);
    let resources = owner.batch();
    let mut budget = CaptureWorkBudget::default();
    let prove = BTreeSet::from([super::key(super::PROVIDER)]);
    let prepared = prepare_confirmation(&mut io, group.tgid, &prove, &mut budget, Some(&resources))
        .expect("member confirm prepares");
    assert!(
        prepared.member.is_some(),
        "segment fallback carries the survivor"
    );
    let mut hook = ZombieUserspaceHook;
    let confirmation = crate::discovery::confirm_shards::prove_and_finish_prepared(
        &mut io,
        group.tgid,
        prepared,
        &mut hook,
        &resources,
        &mut budget,
    );
    let read = match confirmation {
        Confirmation::Confirmed(read) => read,
        other => panic!("segment fallback confirms through member proofs: {other:?}"),
    };
    for entry in super::provider_caller()
        .iter()
        .filter(|entry| is_caller_range(entry))
    {
        if ObjectKey::of(entry) != super::key(super::PROVIDER) {
            continue;
        }
        assert_eq!(
            read.mapped.get(&(entry.start, entry.end)),
            Some(&RangeProof::MapFiles(super::vm_file(super::PROVIDER))),
            "provider text proves through the member: {:?}",
            read.mapped
        );
    }
    assert!(
        !member_reads.borrow().is_empty(),
        "member reads served the fallback"
    );
    assert!(
        leader_reads.borrow().is_empty(),
        "no leader-path range reads: {:?}",
        leader_reads.borrow()
    );
    drop(io);
    assert_eq!(
        owner.state_for_test().0,
        [0; 4],
        "member fallback leaves no shared lease"
    );
    owner
        .reconcile(policy)
        .expect("census passes after member fallback");
}

/// A fresh caller adapter on the production process source, for the
/// cold-admission twins below.
fn cold_caller_adapter() -> crate::discovery::caller_registry::CallerAdapter<
    crate::discovery::caller_registry::OsProcessSource,
> {
    use crate::discovery::caller_registry::{
        CallerAdapter, CallerRegistry, OsProcessSource, RegistryLimits,
    };
    CallerAdapter::new(
        OsProcessSource,
        CallerRegistry::new(RegistryLimits::default_limits()).semantic_storage_reserver(),
    )
}

/// A zombie-leader group parented by a helper child, never by the test:
/// the helper forks the group (one survivor), reports (tgid, survivor)
/// over a pipe, then parks in `pause()`. Killed and reaped on drop; the
/// zombie reparents away once the helper dies.
struct HelperHeldZombie {
    helper: u32,
    tgid: u32,
    survivor: u32,
}

impl HelperHeldZombie {
    fn spawn() -> Self {
        let (mut pipes, mut report) = ([0; 2], [0u8; 8]);
        // SAFETY: two valid two-element arrays for pipe2.
        assert_eq!(
            unsafe { libc::pipe2(pipes.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        // SAFETY: the child only runs the fork-safe group spawn, one
        // pipe write, and `pause()`; no pthread, no locks.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "helper fork failed");
        if pid == 0 {
            unsafe {
                libc::close(pipes[0]);
            }
            let (tgid, survivors) = ZombieLeaderGroup::spawn_inner(1);
            let mut report = [0u8; 8];
            report[0..4].copy_from_slice(&tgid.to_ne_bytes());
            report[4..8].copy_from_slice(&survivors[0].to_ne_bytes());
            let mut written = 0;
            while written < report.len() {
                // SAFETY: writing the stack bytes to the pipe.
                let done = unsafe {
                    libc::write(
                        pipes[1],
                        report.as_ptr().add(written).cast(),
                        report.len() - written,
                    )
                };
                assert!(done > 0, "helper never reported its group");
                written += done as usize;
            }
            loop {
                unsafe {
                    libc::pause();
                }
            }
        }
        // SAFETY: the parent keeps the read end and closes its write copy.
        unsafe {
            libc::close(pipes[1]);
        }
        let mut done = 0;
        while done < report.len() {
            // SAFETY: reading into a valid stack buffer.
            let got = unsafe {
                libc::read(
                    pipes[0],
                    report.as_mut_ptr().add(done).cast(),
                    report.len() - done,
                )
            };
            assert!(got > 0, "helper never reported its group");
            done += got as usize;
        }
        // SAFETY: the read end served its single report.
        unsafe {
            libc::close(pipes[0]);
        }
        Self {
            helper: pid as u32,
            tgid: u32::from_ne_bytes(report[0..4].try_into().expect("tgid bytes")),
            survivor: u32::from_ne_bytes(report[4..8].try_into().expect("tid bytes")),
        }
    }
}

impl Drop for HelperHeldZombie {
    fn drop(&mut self) {
        unsafe {
            // SIGKILL to the TGID stops the survivor; the leader is dead.
            libc::kill(self.tgid as libc::pid_t, libc::SIGKILL);
            libc::kill(self.helper as libc::pid_t, libc::SIGKILL);
            let mut status = 0;
            while libc::waitpid(self.helper as libc::pid_t, &mut status, 0) < 0 {
                let err = std::io::Error::last_os_error().raw_os_error();
                if err == Some(libc::ECHILD) {
                    break;
                }
                assert_eq!(err, Some(libc::EINTR));
            }
        }
        // Bounded hygiene: the reparented zombie is reaped elsewhere.
        let deadline = Instant::now() + Duration::from_secs(10);
        while std::fs::metadata(format!("/proc/{}", self.tgid)).is_ok() {
            assert!(
                Instant::now() < deadline,
                "reparented zombie {} never reaped",
                self.tgid
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// Cold admission mints group ownership only through the TGID's own task
/// listing plus the birth bracket — never by opening /proc/<TID>
/// directly and never by parentage alone. Admitting the bare survivor
/// TID mints no caller for the group, while the TGID itself cold-admits
/// with the survivor-served image — including a group the observer
/// never parented, which parentage alone could never reach.
#[test]
fn cold_admission_refuses_direct_proc_tid_lookup() {
    use crate::discovery::caller_registry::ImageAuthority;
    let group = ZombieLeaderGroup::spawn();
    wait_leader_zombie(group.tgid);
    assert_lone_survivor(&group);
    // The shortcut: admit the bare survivor TID. Whatever it concludes
    // about the TID itself, it must never mint the GROUP.
    let mut tid_adapter = cold_caller_adapter();
    let _ = tid_adapter.admit(group.survivor, ImageAuthority::ScanPinned, 10);
    assert!(
        tid_adapter.live_id(group.tgid).is_none(),
        "a direct /proc/<TID> lookup minted group ownership for {}",
        group.tgid
    );
    // The TGID itself cold-admits with no pre-exit custody: the record
    // names the leader generation with the survivor-served image (the
    // fixture never execs, so it equals this process's own image).
    let mut cold = cold_caller_adapter();
    let id = cold
        .admit(group.tgid, ImageAuthority::ScanPinned, 20)
        .expect("the lone-survivor TGID cold-admits");
    let record = cold.record(id).expect("the cold record is retained");
    assert_eq!(record.pid, group.tgid);
    assert_eq!(
        record.start_time,
        crate::process::process_start_time(group.tgid).ok(),
        "the cold record binds the leader birth"
    );
    assert_eq!(
        record.exe,
        crate::discovery::caller_registry::read_exe_identity(std::process::id()),
        "the cold record carries the survivor-served image"
    );
    assert!(record.exec_observed, "the cold image was observed");
    // No parentage: a helper-held group — never our child — admits
    // through the same TGID proof, which consults no parentage.
    let foreign = HelperHeldZombie::spawn();
    wait_leader_zombie(foreign.tgid);
    assert_ne!(
        foreign.survivor, foreign.tgid,
        "the foreign survivor is a nonleader"
    );
    let foreign_tasks: Vec<u32> = std::fs::read_dir(format!("/proc/{}/task", foreign.tgid))
        .expect("the foreign task list reads")
        .map(|entry| {
            entry
                .expect("entry reads")
                .file_name()
                .to_string_lossy()
                .parse()
                .expect("numeric task id")
        })
        .collect();
    assert!(
        foreign_tasks.contains(&foreign.survivor),
        "the foreign survivor {} is listed in {foreign_tasks:?}",
        foreign.survivor
    );
    let mut foreign_adapter = cold_caller_adapter();
    let foreign_id = foreign_adapter
        .admit(foreign.tgid, ImageAuthority::ScanPinned, 30)
        .expect("cold admission needs no parentage");
    assert_eq!(
        foreign_adapter
            .record(foreign_id)
            .expect("the foreign record is retained")
            .pid,
        foreign.tgid
    );
}

/// Per-lane cold-admission capability (unprivileged): the observer's own
/// forked zombie child exposes the whole cold route — /proc/<tgid>/task
/// lists the survivor while the leader is Z, pidfd_open works post-exit
/// with the pidfd non-ready while threads live, the birth bracket reads —
/// and cold admission consumes it. Fails wherever the route is unavailable.
#[test]
fn cold_admission_task_enumeration_capability() {
    use crate::discovery::caller_registry::ImageAuthority;
    use crate::process::{PidPin, process_is_zombie, process_start_time};
    let group = ZombieLeaderGroup::spawn();
    wait_leader_zombie(group.tgid);
    assert!(
        process_is_zombie(group.tgid),
        "the leader reads Z while the survivor lives"
    );
    assert_lone_survivor(&group);
    let pin = PidPin::open(group.tgid).expect("pidfd_open works on the zombie leader");
    assert!(
        pin.pidfd().is_ok(),
        "the cold pin holds a pidfd, not a proc-only fallback"
    );
    assert!(
        pin.still_the_same(),
        "the pidfd stays non-ready while threads live"
    );
    let birth = process_start_time(group.tgid).expect("the leader birth reads post-exit");
    assert_eq!(pin.start_time(), Some(birth));
    let mut adapter = cold_caller_adapter();
    let id = adapter
        .admit(group.tgid, ImageAuthority::ScanPinned, 10)
        .expect("cold admission consumes the enumerated survivor");
    let record = adapter.record(id).expect("the cold record is retained");
    assert_eq!(record.pid, group.tgid);
    assert_eq!(record.start_time, Some(birth));
}

/// Cold-admission backend parity on Btrfs: the observer holds NO custody
/// before the leader is Z (the first touch of the TGID is the admission
/// itself); after admission both backends show the TGID/held-A positive,
/// exactly like the warm leg — same members, same losses, same proof
/// demand (warm-vs-cold population equivalence). The cold record keeps
/// the leader birth (first-birth selection; the confirm receipt agrees),
/// stays live with no tombstone across reconcile (link loss, not death),
/// and stays out of native revalidation (unproven, never bound on a
/// zombie read). Custody serializes: after both attributions the pin
/// still holds and a fresh prepare still mints.
#[test]
#[ignore = "root Btrfs disk TMPDIR plus eligible BTF/task_vma identity; cold zombie admission parity"]
fn privileged_d4_btrfs_zombie_cold_admission_backend_parity() {
    use crate::discovery::caller_registry::ImageAuthority;
    use crate::discovery::identity::{PinnedObjects, test_fixture::real_scan_pin};
    use crate::discovery::kernel_identity::IdentitySession;
    use sha2::{Digest, Sha256};

    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path();
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    let c_parent = std::ffi::CString::new(parent.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a valid path and writable statfs buffer, read only on success.
    assert_eq!(
        unsafe { libc::statfs(c_parent.as_ptr(), stat.as_mut_ptr()) },
        0
    );
    // SAFETY: initialized by the successful statfs above.
    #[allow(clippy::unnecessary_cast)]
    let magic = unsafe { stat.assume_init().f_type } as u64 & 0xffff_ffff;
    assert_eq!(magic, 0x9123_683e, "actual fixture TMPDIR must be Btrfs");
    let held_path = parent.join("libzombie-cold.so");
    std::fs::write(&held_path, vec![0x5cu8; 8192]).unwrap();

    // Twin mapper groups, each a leader-zombie with one live survivor
    // executably mapping the held file. No custody before leader-Z: the
    // first touch of the cold TGID below is the admission itself.
    let warm = ZombieMapperGroup::spawn(&held_path, true);
    let cold_group = ZombieMapperGroup::spawn(&held_path, true);
    for group in [&warm, &cold_group] {
        wait_leader_zombie(group.tgid);
        assert_mapper_lone_survivor(group);
    }
    let warm_snapshot = warm.maps();
    let cold_snapshot = cold_group.maps();
    for (snapshot, address) in [
        (&warm_snapshot, warm.address),
        (&cold_snapshot, cold_group.address),
    ] {
        let text = snapshot
            .iter()
            .find(|entry| entry.start == address)
            .expect("independent live mapping");
        assert_eq!(text.permissions, *b"r-xp");
    }
    let key = ObjectKey::of(
        warm_snapshot
            .iter()
            .find(|entry| entry.start == warm.address)
            .expect("warm mapping"),
    );
    assert_eq!(
        ObjectKey::of(
            cold_snapshot
                .iter()
                .find(|entry| entry.start == cold_group.address)
                .expect("cold mapping")
        ),
        key,
        "twins map the same held file"
    );

    // Cold admission: the first touch of the TGID. Pre-route this is the
    // failure point (no live process); post-route the record binds the
    // leader birth with the survivor-served image.
    let leader_birth =
        crate::process::process_start_time(cold_group.tgid).expect("the cold leader birth reads");
    let mut adapter = cold_caller_adapter();
    let cold_id = adapter
        .admit(cold_group.tgid, ImageAuthority::ScanPinned, 10)
        .expect("the cold TGID admits with no prior custody");
    let record = adapter
        .record(cold_id)
        .expect("the cold record is retained");
    assert_eq!(record.pid, cold_group.tgid);
    assert_eq!(record.start_time, Some(leader_birth));
    assert_eq!(
        record.exe,
        crate::discovery::caller_registry::read_exe_identity(std::process::id()),
        "the cold record carries the survivor-served image"
    );
    assert_eq!(
        record.lifecycle,
        crate::discovery::caller_registry::CallerLifecycle::Mapped
    );
    // Link loss, not death: reconcile with the TGID observed retires
    // nothing and raises no exit.
    let events = adapter.reconcile(
        &BTreeSet::from([cold_group.tgid]),
        &mut |_| ImageAuthority::ScanPinned,
        20,
    );
    assert!(
        events.is_empty(),
        "the cold record stays live with no tombstone: {events:?}"
    );
    // Unproven for native binding: the live exe read serves nothing for
    // a zombie leader, so the cold caller never revalidates — while a
    // live control in the same adapter does.
    let mut live = std::process::Command::new("sleep")
        .arg("30")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("sleep spawns");
    let live_id = adapter
        .admit(live.id(), ImageAuthority::ScanPinned, 20)
        .expect("the live control admits");
    let revalidated = adapter.revalidate_admitted_before(1_000);
    assert!(
        revalidated.contains(&live_id),
        "the live control revalidates"
    );
    assert!(
        !revalidated.contains(&cold_id),
        "the cold caller stays unproven for native binding"
    );
    // The confirm receipt selects the leader birth too.
    let mut io = OsConfirmIo::default();
    let mut budget = CaptureWorkBudget::default();
    let prepared = prepare_confirmation(
        &mut io,
        cold_group.tgid,
        &BTreeSet::new(),
        &mut budget,
        None,
    )
    .expect("the cold TGID prepares through its member");
    let selector = prepared
        .member
        .as_ref()
        .expect("prepare carries the survivor")
        .selector()
        .expect("carried member selects");
    assert_eq!(selector.tid(), cold_group.survivor);
    let receipt = match finish_confirmation(
        &io,
        cold_group.tgid,
        prepared,
        MappedIdentities::new(),
        None,
        &mut budget,
    ) {
        Confirmation::Confirmed(read) => read,
        other => panic!("the cold confirm seals on member proofs: {other:?}"),
    };
    assert_eq!(receipt.start_time, leader_birth);

    crate::attach::identity_iter::ensure_kernel_identity_btf()
        .expect("required kernel identity capability; refusal cannot qualify");
    let btf = aya::Btf::from_sys_fs().expect("readable host BTF");
    let digest =
        p11scope_manifest::identity::hex(&Sha256::digest(std::fs::read(&held_path).unwrap()));
    let pins: PinnedObjects = real_scan_pin(&held_path, Some(key), 0, &digest);
    let object = pins.pinned().next().expect("actual held-file pin").id;
    let (userspace_index, refused) = KnownKeyIndex::build(
        [(key, Some(object))],
        &BTreeMap::from([(key, object)]),
        [],
        &pins,
    );
    assert!(refused.is_empty(), "{refused:?}");
    assert!(userspace_index.map_files_keys().contains(&key));
    let probe_dir = tempfile::tempdir().unwrap();
    let mut session = IdentitySession::probe_and_load(&btf, probe_dir.path())
        .expect("actual strict-loaded kernel session; no refused/fallback positive");
    // Warm leg first (no admission anywhere near it), then the cold leg:
    // both backends must show the TGID/held-A positive on both.
    let mut legs = Vec::new();
    for (position, (group, snapshot)) in [(&warm, warm_snapshot), (&cold_group, cold_snapshot)]
        .into_iter()
        .enumerate()
    {
        let userspace = d4_zombie_attribute_pid(group.tgid, snapshot.clone(), &userspace_index);
        let kernel = d4_zombie_kernel_attribution_for_pid(
            group.tgid,
            snapshot,
            &pins,
            object,
            key,
            &mut session,
            position as u64 + 1,
        );
        for (backend, out) in [("userspace", &userspace), ("kernel", &kernel)] {
            let members: Vec<_> = out.members.iter().map(|member| member.pid).collect();
            assert_eq!(members, [group.tgid], "{backend} exact zombie caller");
            assert_eq!(
                out.members[0]
                    .objects
                    .iter()
                    .map(|matched| (matched.key, matched.object))
                    .collect::<Vec<_>>(),
                [(key, object)],
                "{backend} exact held original-provider edge"
            );
            assert!(out.losses.is_empty(), "{backend}: {:?}", out.member_losses);
            assert_eq!(out.probed, 1, "{backend} nonempty executable proof demand");
        }
        assert_eq!(
            userspace.members, kernel.members,
            "exact same-population backend members"
        );
        assert_eq!(
            userspace.losses, kernel.losses,
            "same actual loss classifications"
        );
        legs.push((userspace, kernel));
        assert_mapper_lone_survivor(group);
    }
    // Warm-vs-cold population equivalence: the same edge count,
    // losses and demand on each backend, modulo the TGID itself.
    for (backend, warm_leg, cold_leg) in [
        ("userspace", &legs[0].0, &legs[1].0),
        ("kernel", &legs[0].1, &legs[1].1),
    ] {
        assert_eq!(
            (
                warm_leg.members.len(),
                warm_leg.losses.clone(),
                warm_leg.probed
            ),
            (
                cold_leg.members.len(),
                cold_leg.losses.clone(),
                cold_leg.probed
            ),
            "{backend} warm-vs-cold population equivalence"
        );
    }
    // Custody serializes past both attributions: the pin holds and a
    // fresh prepare still mints (no stuck slot, no leaked lease).
    assert!(
        adapter
            .live_pin(cold_group.tgid)
            .is_some_and(|(_, pin)| pin.still_the_same()),
        "the cold pin holds past both attributions"
    );
    let mut io = OsConfirmIo::default();
    let mut budget = CaptureWorkBudget::default();
    let prepared = prepare_confirmation(
        &mut io,
        cold_group.tgid,
        &BTreeSet::new(),
        &mut budget,
        None,
    )
    .expect("a fresh prepare still mints after both attributions");
    assert!(
        prepared.member.is_some(),
        "no stuck member slot past both attributions"
    );
    drop(prepared);
    drop(io);
    eprintln!(
        "D4_ZOMBIE_COLD groups={}/{} userspace=1/1 kernel=1/1 fallback=none",
        warm.tgid, cold_group.tgid
    );
    live.kill().expect("live control dies");
    let _ = live.wait();
    drop((warm, cold_group));
    drop(session);
    drop(pins);
    std::fs::remove_file(&held_path).unwrap();
}

/// Two live survivors refuse cold admission by name — never a pick.
/// Control first: a whole-group-dead zombie refuses with the generic
/// gone message, never the ambiguity name, so the named assertion
/// below discriminates.
#[test]
fn cold_admission_two_survivors_refuses_ambiguity() {
    use crate::discovery::caller_registry::ImageAuthority;
    let mut dead = std::process::Command::new("true")
        .spawn()
        .expect("true spawns");
    let dead_pid = dead.id();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !crate::process::process_is_zombie(dead_pid) {
        assert!(
            Instant::now() < deadline,
            "spawned `true` never showed zombie"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut dead_adapter = cold_caller_adapter();
    let dead_error = dead_adapter
        .admit(dead_pid, ImageAuthority::ScanPinned, 10)
        .unwrap_err();
    let dead_message = format!("{dead_error:#}");
    assert!(
        dead_message.contains("no live process"),
        "dead groups keep the generic gone refusal: {dead_message}"
    );
    assert!(
        !dead_message.contains("more than one live survivor"),
        "dead groups never read ambiguous: {dead_message}"
    );
    assert!(dead_adapter.live_id(dead_pid).is_none());
    dead.wait().expect("the dead control reaps");
    // Then the ambiguous group: two live survivors, one named refusal.
    let group = ZombieLeaderGroup::spawn_two();
    wait_leader_zombie(group.tgid);
    assert_two_survivors(&group);
    let mut adapter = cold_caller_adapter();
    let error = adapter
        .admit(group.tgid, ImageAuthority::ScanPinned, 20)
        .unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("more than one live survivor"),
        "named ambiguity refusal, got {message}"
    );
    assert!(
        adapter.live_id(group.tgid).is_none(),
        "ambiguity never picks a survivor"
    );
}

/// A survivor appearing between the first task listing and the
/// post-mint re-list refuses by the ambiguity name — never a pick of
/// the earlier set. The re-list is scripted (a seam, not timing): the
/// first listing reads the real lone survivor, the mint succeeds on
/// it, and only the second listing shows two. Control: a stable
/// re-list still admits, proving the refused mint released its slot.
#[test]
fn cold_admission_relist_refuses_survivor_appearing_after_mint() {
    use crate::discovery::caller_registry::{cold_admit_member_with_relist, ColdRefusal};
    use crate::process::PidPin;
    use std::sync::Arc;
    let group = ZombieLeaderGroup::spawn();
    wait_leader_zombie(group.tgid);
    assert_lone_survivor(&group);
    let pin = Arc::new(PidPin::open(group.tgid).expect("cold pin opens"));
    // A second TID that is neither the survivor nor the leader: the
    // re-list never mints it, it only compares sets.
    let mut other = group.survivor.wrapping_add(1);
    if other == group.tgid {
        other = other.wrapping_add(1);
    }
    assert_ne!(other, group.survivor);
    let mut work = CaptureWorkBudget::default();
    match cold_admit_member_with_relist(&pin, &mut work, &mut |_| {
        Ok(vec![group.survivor, other])
    }) {
        Err(ColdRefusal::Ambiguous(message)) => assert!(
            message.contains("more than one live survivor"),
            "grown sets refuse by the ambiguity name, got {message}"
        ),
        Err(other) => panic!("a grown task set refuses ambiguous, got {other:?}"),
        Ok(_) => panic!("a grown task set never admits"),
    }
    // Control: a stable re-list still admits (and the refused mint
    // above released its slot, or this mint would refuse).
    let mut work = CaptureWorkBudget::default();
    let minted = cold_admit_member_with_relist(&pin, &mut work, &mut |_| Ok(vec![group.survivor]))
        .expect("a stable re-list still admits");
    let selector = minted
        .member
        .selector()
        .expect("the admitted member selects");
    assert_eq!(selector.tgid(), group.tgid);
    assert_eq!(selector.tid(), group.survivor);
}

/// A cold-minted member handed into the confirm routes the confirm
/// through the survivor. Routing — not just carriage — is pinned with
/// the work budget: the handed path spends 0 mint units while an
/// ordinary mint spends 1 (listing) + 4 (mint), so with the ceiling set
/// to the handed prepare's own spend only the handed path can still
/// carry. Non-vacuity: while the handed member lives, its slot refuses
/// a fresh mint. A handoff for another pid drops and cannot carry under
/// the handed ceiling (control).
#[test]
fn cold_member_handoff_routes_confirm_through_survivor() {
    use crate::discovery::caller_registry::{cold_admit_member, cold_member_owner};
    use crate::discovery::retained_member::RetainedGroupMember;
    use crate::process::PidPin;
    use std::sync::Arc;
    let group = ZombieLeaderGroup::spawn();
    wait_leader_zombie(group.tgid);
    assert_lone_survivor(&group);
    // Cold-mint outside the confirm, from a duplicated pin (never a
    // numeric reopen), and hand it in; the hander's own Arc drops, so
    // only the handed minter sustains the member from here on.
    let pin = Arc::new(PidPin::open(group.tgid).expect("cold pin opens"));
    let mut work = CaptureWorkBudget::default();
    let minted = cold_admit_member(&pin, &mut work).expect("cold mints outside the confirm");
    let rival = Arc::new(pin.try_clone().expect("rival dup"));
    let mut rival_work = CaptureWorkBudget::default();
    let rival_owner = cold_member_owner();
    let rival_deadline = Instant::now() + Duration::from_secs(10);
    assert!(
        RetainedGroupMember::acquire(
            &rival,
            group.survivor,
            &rival_owner,
            &mut rival_work,
            rival_deadline
        )
        .is_err(),
        "the handed slot refuses a fresh mint"
    );
    let mut io = OsConfirmIo::default();
    io.hand_cold_member(group.tgid, minted);
    drop(pin);
    drop(rival);
    let mut budget = CaptureWorkBudget::default();
    let prepared = prepare_confirmation(&mut io, group.tgid, &BTreeSet::new(), &mut budget, None)
        .expect("the handed confirm prepares");
    let selector = prepared
        .member
        .as_ref()
        .expect("prepare carries the handed survivor")
        .selector()
        .expect("carried member selects");
    assert_eq!(selector.tgid(), group.tgid);
    assert_eq!(selector.tid(), group.survivor);
    // The handed path spends 0 mint units, so this ceiling admits no
    // fresh mint (an ordinary mint needs 1 for the listing plus 4 for
    // the mint itself). Pinned at 0 — not just measured — so a dropped
    // handoff cannot inflate the ceiling by silently re-minting: a
    // re-mint would spend 5 here and fail this assert first.
    let handed_spend = budget.work_units_count();
    assert_eq!(
        handed_spend, 0,
        "the handed prepare spends no mint units (a silent re-mint would spend 5)"
    );
    drop(prepared);
    drop(io);
    // Routing pin: under a ceiling of exactly the handed spend, the
    // matching handoff still carries (only the 0-mint-unit handed path
    // fits; a dropped handoff would need 5 more units for a fresh mint).
    // The survivor parks in `pause()` on frozen post-fork mappings, so
    // the maps spend cannot drift between these back-to-back prepares.
    let pin = Arc::new(PidPin::open(group.tgid).expect("second cold pin opens"));
    let mut work = CaptureWorkBudget::default();
    let minted = cold_admit_member(&pin, &mut work).expect("second cold mint");
    let mut io = OsConfirmIo::default();
    io.hand_cold_member(group.tgid, minted);
    drop(pin);
    let mut budget = CaptureWorkBudget::with_work_ceiling(handed_spend);
    let prepared = prepare_confirmation(&mut io, group.tgid, &BTreeSet::new(), &mut budget, None)
        .expect("the handed path fits its own ceiling");
    let selector = prepared
        .member
        .as_ref()
        .expect("the handed path carries under its own ceiling")
        .selector()
        .expect("carried member selects");
    assert_eq!(selector.tgid(), group.tgid);
    assert_eq!(selector.tid(), group.survivor);
    drop(prepared);
    drop(io);
    // Control: a handoff for another pid drops, and the fallback mint
    // cannot carry under the handed ceiling (it needs 5 more units) —
    // while a wrongly accepted handoff WOULD carry (0 mint units).
    let pin = Arc::new(PidPin::open(group.tgid).expect("third cold pin opens"));
    let mut work = CaptureWorkBudget::default();
    let minted = cold_admit_member(&pin, &mut work).expect("third cold mint");
    let mut io = OsConfirmIo::default();
    io.hand_cold_member(group.tgid.wrapping_add(1), minted);
    drop(pin);
    let mut budget = CaptureWorkBudget::with_work_ceiling(handed_spend);
    match prepare_confirmation(&mut io, group.tgid, &BTreeSet::new(), &mut budget, None) {
        Ok(prepared) => assert!(
            prepared.member.is_none(),
            "a dropped handoff carries nothing under the handed ceiling"
        ),
        Err(_) => {}
    }
}

/// A zombie-leader group whose view the test opens while the leader
/// still lives: the forked child blocks on a pipe until released, then
/// raw-clones one survivor (reusing the survivor entry point, which
/// reports its TID over the pipe) and exits its leader thread. Killed
/// and reaped on drop.
struct WarmViewZombie {
    tgid: u32,
    survivor: u32,
}

/// The blocked child before release: closing the pipes or killing
/// the group releases it. Dropped without release on early failure.
/// Two single-direction pipes — a parent-to-child go pipe plus a
/// survivor-to-parent TID pipe — so no read can consume its own
/// side's write.
struct BlockedChild {
    tgid: u32,
    go_write: libc::c_int,
    tid_read: libc::c_int,
}

impl BlockedChild {
    fn fork() -> Self {
        let (mut go, mut tid) = ([0; 2], [0; 2]);
        // SAFETY: two valid two-element arrays for pipe2.
        assert_eq!(unsafe { libc::pipe2(go.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        assert_eq!(unsafe { libc::pipe2(tid.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: the child only reads one go byte, mmaps a stack,
        // clones, and exits its leader thread; no allocator, no
        // pthread, no locks.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "blocked fork failed");
        if pid == 0 {
            let mut go_byte = [0u8; 1];
            unsafe {
                libc::close(go[1]);
                libc::close(tid[0]);
                // One go byte; EOF or error exits instead of hanging.
                let got = libc::read(go[0], go_byte.as_mut_ptr().cast(), go_byte.len());
                if got != go_byte.len() as isize {
                    libc::_exit(1);
                }
                // SAFETY: an anonymous stack mapping, page-aligned.
                let stack = libc::mmap(
                    std::ptr::null_mut(),
                    65536,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                );
                if stack == libc::MAP_FAILED {
                    libc::_exit(2);
                }
                const FLAGS: libc::c_int = libc::CLONE_VM
                    | libc::CLONE_FS
                    | libc::CLONE_FILES
                    | libc::CLONE_SIGHAND
                    | libc::CLONE_THREAD
                    | libc::CLONE_SYSVSEM;
                let cloned = libc::clone(
                    clone_survivor_main,
                    (stack as *mut u8).add(65536).cast(),
                    FLAGS,
                    tid[1] as isize as *mut std::ffi::c_void,
                );
                if cloned < 0 {
                    libc::_exit(3);
                }
                // The main thread exits alone; the survivor keeps the group.
                libc::syscall(libc::SYS_exit, 0);
                libc::_exit(0);
            }
        }
        // SAFETY: the parent keeps one end of each pipe.
        unsafe {
            libc::close(go[0]);
            libc::close(tid[1]);
        }
        Self {
            tgid: pid as u32,
            go_write: go[1],
            tid_read: tid[0],
        }
    }

    /// Release the child: one go byte, then the survivor's TID report.
    /// Waits until the leader reads Z.
    fn release(self) -> WarmViewZombie {
        // SAFETY: writing one go byte down the go pipe.
        assert_eq!(
            unsafe { libc::write(self.go_write, [1u8].as_ptr().cast(), 1) },
            1,
            "the go byte lands"
        );
        let mut tid_bytes = [0u8; 4];
        let mut done = 0;
        while done < tid_bytes.len() {
            // SAFETY: reading into a valid stack buffer; EOF (a dead
            // child) fails loud instead of hanging.
            let got = unsafe {
                libc::read(
                    self.tid_read,
                    tid_bytes.as_mut_ptr().add(done).cast(),
                    tid_bytes.len() - done,
                )
            };
            assert!(got > 0, "the survivor never reported its tid");
            done += got as usize;
        }
        // SAFETY: both ends served their single transfer.
        unsafe {
            libc::close(self.go_write);
            libc::close(self.tid_read);
        }
        let group = WarmViewZombie {
            tgid: self.tgid,
            survivor: u32::from_ne_bytes(tid_bytes),
        };
        std::mem::forget(self);
        wait_leader_zombie(group.tgid);
        group
    }
}

impl Drop for BlockedChild {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.go_write);
            libc::close(self.tid_read);
            libc::kill(self.tgid as libc::pid_t, libc::SIGKILL);
            let mut status = 0;
            while libc::waitpid(self.tgid as libc::pid_t, &mut status, 0) < 0 {
                let err = std::io::Error::last_os_error().raw_os_error();
                if err == Some(libc::ECHILD) {
                    break;
                }
                assert_eq!(err, Some(libc::EINTR));
            }
        }
    }
}

impl Drop for WarmViewZombie {
    fn drop(&mut self) {
        unsafe {
            // SIGKILL to the TGID stops the survivor; the leader is dead.
            libc::kill(self.tgid as libc::pid_t, libc::SIGKILL);
            let mut status = 0;
            while libc::waitpid(self.tgid as libc::pid_t, &mut status, 0) < 0 {
                let err = std::io::Error::last_os_error().raw_os_error();
                if err == Some(libc::ECHILD) {
                    break;
                }
                assert_eq!(err, Some(libc::EINTR));
            }
        }
    }
}

/// A view retained from while the leader lived scans the survivor's
/// maps after the leader exits instead of exiting. Control: once the
/// whole group dies, the same view exits again.
#[test]
fn retained_view_scans_survivor_maps_after_leader_exit() {
    use crate::discovery::hooks::HookRegistry;
    use crate::discovery::scan::{
        CaptureWorkBudget, ScanOutcome, ScanRequest, scan_process_view_without_memory,
    };
    use crate::process::{ProcessView, ProcessViewId};
    let blocked = BlockedChild::fork();
    let tgid = blocked.tgid;
    let view = ProcessView::open(ProcessViewId(7499), tgid).expect("a warm view opens while alive");
    let group = blocked.release();
    assert_eq!(group.tgid, tgid);
    assert_ne!(group.survivor, tgid, "the survivor is a nonleader");
    let hooks = HookRegistry::builtin();
    let request = ScanRequest {
        pid: tgid,
        hints: &[],
        hooks: &hooks,
    };
    let mut budget = CaptureWorkBudget::default();
    let outcome = scan_process_view_without_memory(&request, &view, &mut budget)
        .expect("the retained view scans past the leader exit");
    assert!(
        matches!(outcome, ScanOutcome::Scanned { .. }),
        "survivor maps scan, not an exit: {outcome:?}"
    );
    // Control: once the whole group dies, the same view exits again.
    unsafe {
        libc::kill(tgid as libc::pid_t, libc::SIGKILL);
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while view.still_the_same() {
        assert!(
            Instant::now() < deadline,
            "the killed group never read dead"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    let mut budget = CaptureWorkBudget::default();
    let error = scan_process_view_without_memory(&request, &view, &mut budget).unwrap_err();
    assert!(
        error.contains("exited before discovery"),
        "dead groups still exit the scan: {error}"
    );
}
