//! SPDX-License-Identifier: GPL-3.0-or-later
//! Transient filesystem access for a retained group whose leader exited.

use super::*;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

const MAX_MEMBERS: usize = 128;
const STAT_LIMIT: usize = 4096;
const STATUS_LIMIT: usize = 8192;
const PROOF_GRACE: Duration = Duration::from_secs(1);
const PF_EXITING: u32 = 4;

/// One allowance for an entire serial cold-snapshot stage, never per PID.
pub(crate) fn cold_filesystem_deadline(work: &CaptureWorkBudget) -> Instant {
    let now = Instant::now();
    let grace = now + PROOF_GRACE;
    match work.effective_deadline_ns() {
        Some(limit) => crate::attach::monotonic_ns()
            .and_then(|clock| limit.checked_sub(clock))
            .and_then(|left| now.checked_add(Duration::from_nanos(left)))
            .map_or(now, |deadline| deadline.min(grace)),
        None => grace,
    }
}

/// Advisory snapshots may hold fresh process custody, but return no view,
/// admission or member capability that could renew an older owner.
pub(crate) fn with_cold_snapshot_filesystem<T>(
    pid: u32,
    work: &mut CaptureWorkBudget,
    deadline: Instant,
    read: impl FnOnce(&ViewFilesystem<'_>, &mut CaptureWorkBudget) -> Result<T, String>,
) -> Result<T, String> {
    spend(work, deadline, 1)?;
    let pin = PidPin::open(pid)?;
    let filesystem = ViewFilesystem::open_before(&pin, true, work, deadline, || {})?;
    filesystem.validate(work)?;
    let result = read(&filesystem, work);
    filesystem.validate(work)?;
    result
}

#[derive(Clone, Copy)]
struct Task {
    birth: u64,
    state: u8,
    flags: u32,
}

impl Task {
    fn live(self) -> bool {
        matches!(
            self.state,
            b'R' | b'S' | b'D' | b'T' | b't' | b'I' | b'P' | b'W'
        ) && self.flags & PF_EXITING == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RootIdentity {
    device: u64,
    inode: u64,
    mount: u64,
}

struct Filesystem {
    // Holding this fd prevents namespace-inode reuse during the proof.
    _namespace: std::fs::File,
    root: std::fs::File,
    namespace_id: MountNamespaceId,
    root_id: RootIdentity,
}

struct Member {
    directory: OwnedFd,
    tid: u32,
    birth: u64,
}

struct ColdFilesystem<'a> {
    original: ProcPin<'a>,
    members: Vec<Member>,
    filesystem: Filesystem,
    deadline: Instant,
}

/// This owns no semantic or LIVE_MINTS authority. All cold descriptors are
/// transient and close at the end of one bounded filesystem operation.
pub(crate) struct ViewFilesystem<'a> {
    pin: &'a PidPin,
    namespace: MountNamespaceId,
    cold: Option<ColdFilesystem<'a>>,
}

fn spend(work: &mut CaptureWorkBudget, deadline: Instant, units: u64) -> Result<(), String> {
    if Instant::now() >= deadline {
        return Err("cold process filesystem proof deadline exhausted".into());
    }
    work.spend(units).map_err(str::to_owned)
}

fn fd_path(directory: BorrowedFd<'_>, suffix: &str) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}/{suffix}", directory.as_raw_fd()))
}

fn read_bounded(
    file: std::fs::File,
    limit: usize,
    work: &mut CaptureWorkBudget,
    deadline: Instant,
) -> Result<String, String> {
    spend(work, deadline, 1)?;
    let allowed = work.allowed_io(0, limit + 1);
    if allowed == 0 {
        return Err("cold process filesystem metadata I/O is unavailable".into());
    }
    let mut bytes = Vec::new();
    let read = file.take(allowed as u64).read_to_end(&mut bytes);
    work.record_io(bytes.len());
    read.map_err(|error| format!("cold process filesystem metadata unreadable: {error}"))?;
    spend(work, deadline, 1)?;
    if bytes.len() > limit || bytes.len() == allowed {
        return Err("cold process filesystem metadata is truncated or over budget".into());
    }
    String::from_utf8(bytes).map_err(|error| error.to_string())
}

fn text_at(
    directory: BorrowedFd<'_>,
    name: &std::ffi::CStr,
    limit: usize,
    work: &mut CaptureWorkBudget,
    deadline: Instant,
) -> Result<String, String> {
    spend(work, deadline, 1)?;
    let file = std::fs::File::from(relative_proc_open(directory, name)?);
    read_bounded(file, limit, work, deadline)
}

fn task_at(
    directory: BorrowedFd<'_>,
    name: &std::ffi::CStr,
    work: &mut CaptureWorkBudget,
    deadline: Instant,
) -> Result<Task, String> {
    let stat = text_at(directory, name, STAT_LIMIT, work, deadline)?;
    let end = stat
        .rfind(')')
        .ok_or("cold process task stat is malformed")?;
    Ok(Task {
        birth: start_time_from_stat(&stat).map_err(|error| error.to_string())?,
        state: stat[end + 1..]
            .split_whitespace()
            .next()
            .and_then(|word| word.as_bytes().first())
            .copied()
            .ok_or("cold process task state is unavailable")?,
        flags: stat_flags_from_stat_text(&stat).ok_or("cold process task flags are unavailable")?,
    })
}

fn task_ids(
    original: &ProcPin<'_>,
    work: &mut CaptureWorkBudget,
    deadline: Instant,
) -> Result<Vec<u32>, String> {
    spend(work, deadline, 1)?;
    let entries = std::fs::read_dir(fd_path(original.directory.as_fd(), "task"))
        .map_err(|error| format!("cold process task census unavailable: {error}"))?;
    let mut tids = Vec::new();
    for entry in entries {
        spend(work, deadline, 1)?;
        let tid = entry
            .map_err(|error| error.to_string())?
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
            .ok_or("cold process task census is malformed")?;
        if tid == original.pin.pid() {
            continue;
        }
        if tids.len() == MAX_MEMBERS {
            return Err(
                "cold process filesystem member capacity 128 exhausted; namespace remains unproven"
                    .into(),
            );
        }
        tids.push(tid);
    }
    tids.sort_unstable();
    if tids.is_empty() {
        return Err("cold process filesystem has no proven live nonleader".into());
    }
    Ok(tids)
}

fn filesystem_at(
    member: &Member,
    work: &mut CaptureWorkBudget,
    deadline: Instant,
) -> Result<Filesystem, String> {
    spend(work, deadline, 2)?;
    let namespace = std::fs::File::open(fd_path(member.directory.as_fd(), "ns/mnt"))
        .map_err(|error| format!("cold member mount namespace unavailable: {error}"))?;
    let metadata = namespace.metadata().map_err(|error| error.to_string())?;
    let namespace_id = MountNamespaceId {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    let root = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
        .open(fd_path(member.directory.as_fd(), "root"))
        .map_err(|error| format!("cold member root unavailable: {error}"))?;
    spend(work, deadline, 1)?;
    let metadata = root.metadata().map_err(|error| error.to_string())?;
    let info = std::fs::File::open(format!("/proc/self/fdinfo/{}", root.as_raw_fd()))
        .map_err(|error| error.to_string())?;
    let text = read_bounded(info, STAT_LIMIT, work, deadline)?;
    let mount = text
        .lines()
        .find_map(|line| line.strip_prefix("mnt_id:"))
        .and_then(|value| value.trim().parse().ok())
        .ok_or("cold member root mount identity unavailable")?;
    Ok(Filesystem {
        _namespace: namespace,
        root,
        namespace_id,
        root_id: RootIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            mount,
        },
    })
}

fn same_filesystem(left: &Filesystem, right: &Filesystem) -> bool {
    left.namespace_id == right.namespace_id && left.root_id == right.root_id
}

impl ColdFilesystem<'_> {
    fn validate(&self, work: &mut CaptureWorkBudget) -> Result<(), String> {
        self.validate_with(work, &mut filesystem_at)
    }

    fn validate_with(
        &self,
        work: &mut CaptureWorkBudget,
        read_filesystem: &mut impl FnMut(
            &Member,
            &mut CaptureWorkBudget,
            Instant,
        ) -> Result<Filesystem, String>,
    ) -> Result<(), String> {
        let deadline = self.deadline;
        spend(work, deadline, 1)?;
        if self.original.pin.original_exited()? {
            return Err("original process exited during cold filesystem proof".into());
        }
        let leader = task_at(self.original.directory.as_fd(), c"stat", work, deadline)?;
        if Some(leader.birth) != self.original.pin.start_time() || leader.state != b'Z' {
            return Err("cold process leader generation or Z boundary changed".into());
        }
        let tids = task_ids(&self.original, work, deadline)?;
        if tids
            != self
                .members
                .iter()
                .map(|member| member.tid)
                .collect::<Vec<_>>()
        {
            return Err("cold process task census changed; filesystem remains unproven".into());
        }
        for member in &self.members {
            let stat = task_at(member.directory.as_fd(), c"stat", work, deadline)?;
            if stat.birth != member.birth || !stat.live() {
                return Err("cold process member generation or liveness changed".into());
            }
            let status = text_at(
                member.directory.as_fd(),
                c"status",
                STATUS_LIMIT,
                work,
                deadline,
            )?;
            let tgid = status
                .lines()
                .find_map(|line| line.strip_prefix("Tgid:"))
                .and_then(|value| value.trim().parse::<u32>().ok());
            if tgid != Some(self.original.pin.pid()) {
                return Err(
                    "cold process member no longer proves original group membership".into(),
                );
            }
            let fresh = read_filesystem(member, work, deadline)?;
            if !same_filesystem(&self.filesystem, &fresh) {
                return Err("cold process filesystem is ambiguous: live members do not share one mount namespace and root".into());
            }
            let after = task_at(member.directory.as_fd(), c"stat", work, deadline)?;
            if after.birth != member.birth || !after.live() {
                return Err("cold process member changed while its filesystem was checked".into());
            }
        }
        if task_ids(&self.original, work, deadline)? != tids {
            return Err("cold process task census changed; filesystem remains unproven".into());
        }
        let leader = task_at(self.original.directory.as_fd(), c"stat", work, deadline)?;
        if Some(leader.birth) != self.original.pin.start_time() || leader.state != b'Z' {
            return Err("cold process leader generation or Z boundary changed".into());
        }
        spend(work, deadline, 1)?;
        if self.original.pin.original_exited()? {
            return Err("original process exited during cold filesystem proof".into());
        }
        Ok(())
    }
}

impl<'a> ViewFilesystem<'a> {
    pub(crate) fn open(pin: &'a PidPin, work: &mut CaptureWorkBudget) -> Result<Self, String> {
        Self::open_required(pin, false, work)
    }

    pub(crate) fn open_required(
        pin: &'a PidPin,
        require_cold: bool,
        work: &mut CaptureWorkBudget,
    ) -> Result<Self, String> {
        let deadline = cold_filesystem_deadline(work);
        Self::open_before(pin, require_cold, work, deadline, || {})
    }

    pub(crate) fn open_for_view(
        pin: &'a PidPin,
        require_cold: bool,
        work: &mut CaptureWorkBudget,
        observed_z: impl FnOnce(),
    ) -> Result<Self, String> {
        let deadline = cold_filesystem_deadline(work);
        Self::open_before(pin, require_cold, work, deadline, observed_z)
    }

    fn open_before(
        pin: &'a PidPin,
        require_cold: bool,
        work: &mut CaptureWorkBudget,
        deadline: Instant,
        observed_z: impl FnOnce(),
    ) -> Result<Self, String> {
        let deadline = deadline.min(cold_filesystem_deadline(work));
        if !require_cold && let Ok(namespace) = mount_namespace_id(pin.pid()) {
            if pin.original_exited()? {
                return Err("original process exited while its filesystem was identified".into());
            }
            return Ok(Self {
                pin,
                namespace,
                cold: None,
            });
        }
        spend(work, deadline, 3)?;
        let original = pin.open_proc_dir()?;
        let leader = task_at(original.directory.as_fd(), c"stat", work, deadline)?;
        if Some(leader.birth) != pin.start_time() || leader.state != b'Z' {
            return Err("cold process filesystem requires the original leader at Z".into());
        }
        // A later refusal stays unknown, but cannot erase this one-way
        // boundary and let an EXEC successor renew the old view.
        observed_z();
        let mut members = Vec::new();
        for tid in task_ids(&original, work, deadline)? {
            let relative = std::ffi::CString::new(format!("task/{tid}")).unwrap();
            let before = task_at(
                original.directory.as_fd(),
                &std::ffi::CString::new(format!("task/{tid}/stat")).unwrap(),
                work,
                deadline,
            )?;
            if !before.live() {
                return Err(
                    "cold process task census contains an unproven or exiting member".into(),
                );
            }
            spend(work, deadline, 1)?;
            let directory = relative_proc_open(original.directory.as_fd(), &relative)?;
            let after = task_at(directory.as_fd(), c"stat", work, deadline)?;
            if before.birth != after.birth || !after.live() {
                return Err("cold process member changed during directory acquisition".into());
            }
            members.push(Member {
                directory,
                tid,
                birth: after.birth,
            });
        }
        let filesystem = filesystem_at(&members[0], work, deadline)?;
        let cold = ColdFilesystem {
            original,
            members,
            filesystem,
            deadline,
        };
        cold.validate(work)?;
        Ok(Self {
            pin,
            namespace: cold.filesystem.namespace_id,
            cold: Some(cold),
        })
    }

    pub(crate) fn namespace(&self) -> MountNamespaceId {
        self.namespace
    }

    pub(crate) fn is_cold(&self) -> bool {
        self.cold.is_some()
    }

    pub(crate) fn validate(&self, work: &mut CaptureWorkBudget) -> Result<(), String> {
        match &self.cold {
            Some(cold) => cold.validate(work),
            None if !self.pin.original_exited()? => {
                ensure_same_mount_namespace(self.namespace, mount_namespace_id(self.pin.pid())?)
            }
            None => Err("original process exited during filesystem access".into()),
        }
    }

    fn owned_path(&self, name: &str) -> PathBuf {
        match &self.cold {
            Some(cold) => fd_path(cold.members[0].directory.as_fd(), name),
            None => PathBuf::from(format!("/proc/{}/{name}", self.pin.pid())),
        }
    }

    pub(crate) fn open_maps(&self) -> std::io::Result<std::fs::File> {
        std::fs::File::open(self.owned_path("maps"))
    }

    pub(crate) fn open_memory(&self) -> std::io::Result<std::fs::File> {
        std::fs::File::open(self.owned_path("mem"))
    }

    pub(crate) fn open_executable(&self) -> std::io::Result<std::fs::File> {
        std::fs::File::open(self.owned_path("exe"))
    }

    pub(crate) fn open_mountinfo(&self) -> std::io::Result<std::fs::File> {
        std::fs::File::open(self.owned_path("mountinfo"))
    }

    pub(crate) fn mapped_file_metadata(
        &self,
        start: u64,
        end: u64,
        work: &mut CaptureWorkBudget,
    ) -> std::io::Result<std::fs::Metadata> {
        if start >= end || start & 4095 != 0 || end & 4095 != 0 {
            return Err(io::Error::other("invalid retained mapped range"));
        }
        let Some(cold) = &self.cold else {
            return std::fs::metadata(self.owned_path(&format!("map_files/{start:x}-{end:x}")));
        };
        let member = &cold.members[0];
        let prove =
            |directory: BorrowedFd<'_>, work: &mut CaptureWorkBudget| -> Result<(), String> {
                let stat = task_at(directory, c"stat", work, cold.deadline)?;
                let status = text_at(directory, c"status", STATUS_LIMIT, work, cold.deadline)?;
                let tgid = status
                    .lines()
                    .find_map(|line| line.strip_prefix("Tgid:"))
                    .and_then(|value| value.trim().parse::<u32>().ok());
                if stat.birth != member.birth || !stat.live() || tgid != Some(self.pin.pid()) {
                    return Err(
                        "TID proc directory does not prove the retained live group member".into(),
                    );
                }
                Ok(())
            };
        spend(work, cold.deadline, 1).map_err(io::Error::other)?;
        let directory = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(format!("/proc/{}", member.tid))?;
        prove(directory.as_fd(), work).map_err(io::Error::other)?;
        let metadata = std::fs::metadata(fd_path(
            directory.as_fd(),
            &format!("map_files/{start:x}-{end:x}"),
        ));
        prove(directory.as_fd(), work).map_err(io::Error::other)?;
        metadata
    }

    pub(crate) fn open_rooted(&self, path: &Path) -> Result<std::fs::File, String> {
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, Component::ParentDir | Component::Prefix(_)))
        {
            return Err(
                "target-root object requires an absolute path without parent traversal".into(),
            );
        }
        let relative = path.strip_prefix("/").map_err(|error| error.to_string())?;
        let ordinary_root;
        let root = match &self.cold {
            Some(cold) => &cold.filesystem.root,
            None => {
                ordinary_root = std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
                    .open(self.owned_path("root"))
                    .map_err(|error| error.to_string())?;
                &ordinary_root
            }
        };
        let name = std::ffi::CString::new(relative.as_os_str().as_encoded_bytes())
            .map_err(|error| error.to_string())?;
        #[repr(C)]
        struct OpenHow {
            flags: u64,
            mode: u64,
            resolve: u64,
        }
        let how = OpenHow {
            flags: (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOCTTY) as u64,
            mode: 0,
            // Resolve symlinks within the held target root; magic links
            // cannot redirect an internally scoped target open elsewhere.
            resolve: 0x10 | 0x02, // RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS
        };
        // SAFETY: live root fd, bounded NUL-terminated relative name, and
        // the kernel's fixed open_how layout. No failure has a loose fallback.
        let result = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                root.as_raw_fd(),
                name.as_ptr(),
                &how,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if result < 0 {
            return Err(format!(
                "opening object within retained target root: {}",
                io::Error::last_os_error()
            ));
        }
        // SAFETY: successful openat2 returned a newly owned descriptor.
        let file = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(result as i32) });
        if !file
            .metadata()
            .map_err(|error| error.to_string())?
            .is_file()
        {
            return Err("target-root object is not a regular file".into());
        }
        Ok(file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::cold_view_tests::ColdLeaderSubject;

    #[test]
    fn an_expired_shared_snapshot_cutoff_is_not_renewed_for_a_pid() {
        let mut group = ColdLeaderSubject::spawn(1);
        group.leave_leader();
        let mut work = CaptureWorkBudget::default();
        let called = std::cell::Cell::new(false);
        let expired = Instant::now() - Duration::from_millis(1);
        assert!(
            with_cold_snapshot_filesystem(group.pid(), &mut work, expired, |_, _| {
                called.set(true);
                Ok(())
            })
            .is_err()
        );
        assert!(
            !called.get(),
            "a spent stage cannot perform another PID read"
        );
        let deadline = cold_filesystem_deadline(&work);
        with_cold_snapshot_filesystem(group.pid(), &mut work, deadline, |filesystem, _| {
            filesystem.open_maps().map_err(|error| error.to_string())?;
            called.set(true);
            Ok(())
        })
        .unwrap();
        assert!(called.get(), "a fresh explicit stage still works");
        group.call_three();
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn cold_filesystem_reads_actual_sparse_table_and_target_root_object() {
        use std::os::unix::fs::FileExt;
        for workers in [1, 2] {
            let mut group = ColdLeaderSubject::spawn(workers);
            group.leave_leader();
            let pin = PidPin::open(group.pid()).unwrap();
            let mut work = CaptureWorkBudget::default();
            let proof = ViewFilesystem::open(&pin, &mut work).unwrap();
            proof.validate(&mut work).unwrap();
            let memory = proof
                .open_memory()
                .expect("the proven member serves the shared address space");
            let mut body = [0; 8 + 68 * 8];
            memory
                .read_exact_at(&mut body, group.table_address)
                .unwrap();
            assert_eq!(body[..2], [3, 2]);
            assert_ne!(u64::from_le_bytes(body[8..16].try_into().unwrap()), 0);
            assert!(body[16..].iter().all(|byte| *byte == 0));
            let object = proof
                .open_rooted(&group.program)
                .expect("the held target root opens its actual provider");
            let actual = object.metadata().unwrap();
            let expected = group.program.metadata().unwrap();
            assert_eq!(
                (actual.dev(), actual.ino()),
                (expected.dev(), expected.ino())
            );
            proof.validate(&mut work).unwrap();
            group.call_three();
        }
    }

    #[test]
    fn second_worker_namespace_root_and_unreadable_facts_cannot_be_skipped() {
        let mut group = ColdLeaderSubject::spawn(2);
        group.leave_leader();
        let pin = PidPin::open(group.pid()).unwrap();
        for change in 0..4 {
            let mut work = CaptureWorkBudget::default();
            let proof = ViewFilesystem::open(&pin, &mut work).unwrap();
            let cold = proof.cold.as_ref().unwrap();
            let second = cold.members[1].tid;
            let error = cold
                .validate_with(&mut work, &mut |member, work, deadline| {
                    let mut facts = filesystem_at(member, work, deadline)?;
                    if member.tid == second {
                        match change {
                            0 => facts.namespace_id.inode ^= 1,
                            1 => facts.root_id.inode ^= 1,
                            2 => facts.root_id.mount ^= 1,
                            _ => return Err("scripted second-worker metadata refusal".into()),
                        }
                    }
                    Ok(facts)
                })
                .unwrap_err();
            assert!(
                error.contains(if change == 3 {
                    "metadata refusal"
                } else {
                    "ambiguous"
                }),
                "{error}"
            );
            cold.validate(&mut work)
                .expect("a refusal leaves real healthy custody usable");
        }
        group.call_three();
    }

    #[test]
    fn changed_member_birth_cannot_reuse_original_group_authority() {
        let mut group = ColdLeaderSubject::spawn(2);
        group.leave_leader();
        let pin = PidPin::open(group.pid()).unwrap();
        let mut work = CaptureWorkBudget::default();
        let mut proof = ViewFilesystem::open(&pin, &mut work).unwrap();
        proof.cold.as_mut().unwrap().members[1].birth ^= 1;
        assert!(
            proof
                .validate(&mut work)
                .unwrap_err()
                .contains("generation")
        );
        assert_eq!(
            pin.original_exited(),
            Ok(false),
            "a live group pin does not waive a changed member"
        );
        drop(proof);
        ViewFilesystem::open(&pin, &mut work)
            .unwrap()
            .validate(&mut work)
            .unwrap();
        group.call_three();
    }

    #[test]
    fn actual_member_exit_refuses_old_proof_while_another_worker_keeps_group_alive() {
        let mut group = ColdLeaderSubject::spawn(2);
        group.leave_leader();
        let pin = PidPin::open(group.pid()).unwrap();
        let mut work = CaptureWorkBudget::default();
        let proof = ViewFilesystem::open(&pin, &mut work).unwrap();
        group.exit_one_worker();
        assert_eq!(pin.original_exited(), Ok(false));
        assert!(
            proof.validate(&mut work).is_err(),
            "pidfd unreadiness cannot waive a disappeared member"
        );
        drop(proof);
        ViewFilesystem::open(&pin, &mut work)
            .unwrap()
            .validate(&mut work)
            .unwrap();
        group.call_three();
    }

    #[test]
    fn scoped_target_paths_reject_parent_traversal_before_open() {
        let mut group = ColdLeaderSubject::spawn(1);
        group.leave_leader();
        let pin = PidPin::open(group.pid()).unwrap();
        let mut work = CaptureWorkBudget::default();
        let proof = ViewFilesystem::open(&pin, &mut work).unwrap();
        for path in ["relative", "/../outside", "/owned/../../outside"] {
            let error = proof.open_rooted(Path::new(path)).unwrap_err();
            assert!(error.contains("without parent traversal"), "{error}");
        }
        proof.validate(&mut work).unwrap();
        group.call_three();
    }
}
