//! SPDX-License-Identifier: GPL-3.0-or-later
//! D4 zombie cells: leader-zombie groups with live survivors. Ordinary
//! twins pin the sweep-seam classification (a group without a live member
//! stays exited; a live survivor prepares through retained-member custody
//! without disturbing the shared census; two survivors mint no member);
//! the ignored twin asserts backend parity for collision/data-only zombie
//! mappings on Btrfs.

use super::*;
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

struct ZombieProofPin;

/// `ConfirmIo` whose leader-path range reads fail exactly like the real
/// kernel for a zombie leader (ESRCH) and whose member-path reads
/// succeed with the canned per-inode identity. Mint acquires the real
/// survivor, so routing (stash vs leader) is what the tests pin.
struct ZombieProofIo {
    entries: Vec<MapEntry>,
    survivor: u32,
    member_owner: ReservationOwner,
    stashed: Option<crate::discovery::retained_member::RetainedGroupMember>,
    minter: Option<std::sync::Arc<crate::process::PidPin>>,
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
            member_owner: ReservationOwner::new(SegmentPolicy::from_headroom(64, 1, 1)),
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

    fn open(&mut self, _: u32) -> Result<Self::Pin, String> {
        Ok(ZombieProofPin)
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
        budget: &mut CaptureWorkBudget,
    ) -> Result<(), Confirmation> {
        use crate::discovery::retained_member::RetainedGroupMember;
        self.stashed = None;
        self.minter = None;
        if !crate::process::process_is_zombie(pid) {
            return Ok(());
        }
        let original =
            std::sync::Arc::new(crate::process::PidPin::open(pid).map_err(|error| {
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
                self.minter = Some(original);
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
