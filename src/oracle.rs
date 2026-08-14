use crate::attach::Scope;
use anyhow::{Context as _, Result, anyhow};
use p11scope_manifest::identity::{
    ElfLoader, MappingFileKey, inspect_elf_loader, mapping_file_key,
};
use p11scope_manifest::manifest::ProvenanceObject;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::File;
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::FileExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path, PathBuf};

const GLIBC_INTERP: &str = "/lib64/ld-linux-x86-64.so.2";
const GLIBC_LOADER: &str = "ld-linux-x86-64.so.2";
const GLIBC_SEARCH_DIRECTORIES: [&str; 2] = ["/usr/lib/x86_64-linux-gnu", "/usr/lib64"];
const GLIBC_STAGING_DIRECTORY: &str = "/run/p11scope";
const MAX_SYMLINK_HOPS: usize = 8;
const MAX_PROC_STATUS_BYTES: usize = 64 * 1024;
const MAX_PROC_STAT_BYTES: usize = 4 * 1024;
const MAX_TARGET_TASKS: usize = 16_384;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OracleMode {
    TrustedWorkload,
    Hardened,
}

#[derive(Debug)]
pub struct OracleSelection {
    mode: OracleMode,
    target: Option<PinnedTarget>,
}

struct HardenedFacts<'a> {
    observer_loader: ElfLoader,
    observer_owner: u32,
    observer_mode: u32,
    observer_status: &'a str,
    target_status: &'a str,
    observer_uid_map: &'a str,
    observer_user_namespace: (u64, u64),
    init_user_namespace: (u64, u64),
}

#[derive(Debug, PartialEq, Eq)]
struct ProcessStatus {
    uids: [u32; 4],
    capabilities: u64,
    no_new_privileges: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcFileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TargetIdentity {
    directory: ProcFileIdentity,
    status: ProcFileIdentity,
    tasks: ProcFileIdentity,
    start_time: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TaskIdentity {
    directory: ProcFileIdentity,
    status: ProcFileIdentity,
    start_time: u64,
}

type TaskIdentitySet = BTreeMap<u32, TaskIdentity>;

#[derive(Debug)]
struct PinnedTarget {
    pid: u32,
    pidfd: OwnedFd,
    procfs: File,
    directory: File,
    status: File,
    tasks: File,
    identity: TargetIdentity,
}

#[allow(dead_code, reason = "private one-pass seam awaiting C3.3B wiring")]
pub(crate) struct HardenedChildProcess {
    directory: File,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "private one-pass seam awaiting C3.3B wiring")]
pub(crate) struct ProcFdIdentity {
    pub(crate) device: libc::dev_t,
    pub(crate) inode: libc::ino_t,
    pub(crate) kind: libc::mode_t,
}

fn trusted_required(reason: impl std::fmt::Display) -> anyhow::Error {
    anyhow!(
        "{reason}; pass --trusted-workload only when the observed workload is explicitly trusted"
    )
}

impl OracleSelection {
    fn trusted_workload() -> Self {
        Self {
            mode: OracleMode::TrustedWorkload,
            target: None,
        }
    }

    fn hardened(target: PinnedTarget) -> Self {
        Self {
            mode: OracleMode::Hardened,
            target: Some(target),
        }
    }

    pub(crate) fn mode(&self) -> OracleMode {
        self.mode
    }

    pub fn revalidate(&self) -> Result<()> {
        match (self.mode, &self.target) {
            (OracleMode::TrustedWorkload, None) => Ok(()),
            (OracleMode::Hardened, Some(target)) => target.revalidate(),
            _ => Err(anyhow!(
                "discovery oracle selection has inconsistent target authority"
            )),
        }
    }

    #[cfg(test)]
    pub(crate) fn hardened_without_target_for_test() -> Self {
        Self {
            mode: OracleMode::Hardened,
            target: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn hardened_for_pid_for_test(pid: u32) -> Result<Self> {
        Ok(Self::hardened(PinnedTarget::pin(pid)?))
    }

    #[allow(dead_code, reason = "private one-pass seam awaiting C3.3B wiring")]
    pub(crate) fn open_hardened_child(&self, pid: u32) -> Result<HardenedChildProcess> {
        let target = self
            .target
            .as_ref()
            .ok_or_else(|| anyhow!("hardened oracle selection has no retained target authority"))?;
        target.revalidate()?;
        validate_procfs_binding(&target.procfs)?;
        Ok(HardenedChildProcess {
            directory: open_proc_pid_directory(&target.procfs, pid)?,
        })
    }
}

#[allow(dead_code, reason = "private one-pass seam awaiting C3.3B wiring")]
impl HardenedChildProcess {
    pub(crate) fn maps(&self) -> Result<File> {
        open_proc_regular(&self.directory, "maps")
    }

    pub(crate) fn exe_key(&self) -> Result<MappingFileKey> {
        let exe = openat_file(&self.directory, "exe", libc::O_RDONLY)?;
        mapping_file_key(&exe).map_err(anyhow::Error::msg)
    }

    pub(crate) fn fd_identities(&self) -> Result<BTreeMap<RawFd, ProcFdIdentity>> {
        let directory = open_proc_directory(&self.directory, "fd")?;
        let mut result = BTreeMap::new();
        for name in directory_entry_names(&directory, MAX_TARGET_TASKS, "hardened child fd")? {
            let bytes = name.as_bytes();
            if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
                return Err(anyhow!(
                    "hardened child fd directory has a non-numeric entry"
                ));
            }
            let text = std::str::from_utf8(bytes)
                .map_err(|_| anyhow!("hardened child fd is not UTF-8"))?;
            let fd: RawFd = text
                .parse()
                .map_err(|_| anyhow!("hardened child fd is out of range"))?;
            if fd < 0 || fd.to_string() != text {
                return Err(anyhow!("hardened child fd is not canonical"));
            }
            let name = CString::new(bytes).expect("numeric fd has no NUL");
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstatat(directory.as_raw_fd(), name.as_ptr(), &mut stat, 0) } == -1 {
                return Err(std::io::Error::last_os_error())
                    .with_context(|| format!("identifying hardened child fd {fd}"));
            }
            if result
                .insert(
                    fd,
                    ProcFdIdentity {
                        device: stat.st_dev,
                        inode: stat.st_ino,
                        kind: stat.st_mode & libc::S_IFMT,
                    },
                )
                .is_some()
            {
                return Err(anyhow!("hardened child fd directory has duplicate entries"));
            }
        }
        Ok(result)
    }

    pub(crate) fn memory_identity(&self) -> Result<ProcFdIdentity> {
        let stat = stat_at(&self.directory, &CString::new("mem").unwrap())
            .context("identifying hardened child self-memory")?;
        Ok(ProcFdIdentity {
            device: stat.st_dev,
            inode: stat.st_ino,
            kind: stat.st_mode & libc::S_IFMT,
        })
    }
}

impl PinnedTarget {
    fn pin(pid: u32) -> Result<Self> {
        let pidfd = open_pidfd(pid)?;
        ensure_pid_alive(pid, &pidfd)?;
        let procfs = open_procfs()?;
        let directory = open_proc_pid_directory(&procfs, pid)?;
        let status = open_proc_regular(&directory, "status")?;
        let tasks = open_proc_directory(&directory, "task")?;
        let identity = target_identity(&directory, &status, &tasks)?;
        let target = Self {
            pid,
            pidfd,
            procfs,
            directory,
            status,
            tasks,
            identity,
        };
        target.revalidate()?;
        Ok(target)
    }

    fn revalidate(&self) -> Result<()> {
        ensure_pid_alive(self.pid, &self.pidfd)?;
        validate_procfs_binding(&self.procfs)?;
        let retained = TargetIdentity {
            directory: proc_file_identity(&self.directory)?,
            status: proc_file_identity(&self.status)?,
            tasks: proc_file_identity(&self.tasks)?,
            start_time: self.identity.start_time,
        };
        ensure_same_target(self.pid, self.identity, retained)?;
        let directory = open_proc_pid_directory(&self.procfs, self.pid)?;
        let status = open_proc_regular(&directory, "status")?;
        let tasks = open_proc_directory(&directory, "task")?;
        let current = target_identity(&directory, &status, &tasks)?;
        ensure_same_target(self.pid, self.identity, current)?;
        let first = validated_task_set(&self.tasks, self.pid)?;
        let second = validated_task_set(&self.tasks, self.pid)?;
        ensure_same_task_set(self.pid, &first, &second)?;
        ensure_pid_alive(self.pid, &self.pidfd)
    }

    fn status(&self) -> Result<String> {
        read_proc_text(&self.status, MAX_PROC_STATUS_BYTES, "process status")
    }
}

fn validate_target_status(status: &ProcessStatus) -> Result<()> {
    if status.uids.contains(&0) {
        return Err(anyhow!(
            "the observed process has a root UID and can share authority with the observer",
        ));
    }
    if status.capabilities != 0 {
        return Err(anyhow!(
            "the observed process has capabilities that can regain authority over the observer",
        ));
    }
    if !status.no_new_privileges {
        return Err(anyhow!(
            "the observed process does not have NoNewPrivs enabled",
        ));
    }
    Ok(())
}

fn select_from_facts(
    scope: &Scope,
    trusted_workload: bool,
    facts: Option<HardenedFacts<'_>>,
) -> Result<OracleMode> {
    let eligible = (|| -> Result<()> {
        if matches!(scope, Scope::Cgroup { .. }) {
            return Err(anyhow!(
                "hostile-workload oracle mode cannot prove the identity of future cgroup members"
            ));
        }
        let facts = facts.ok_or_else(|| anyhow!("hardened oracle facts are unavailable"))?;
        if facts.observer_loader.interpreter.is_some() || !facts.observer_loader.needed.is_empty() {
            return Err(anyhow!(
                "hostile-workload oracle mode requires the fully static observer",
            ));
        }
        if facts.observer_owner != 0
            || facts.observer_mode & libc::S_IFMT != libc::S_IFREG
            || facts.observer_mode & 0o022 != 0
        {
            return Err(anyhow!(
                "hostile-workload oracle mode requires a root-owned non-group/world-writable observer",
            ));
        }
        let observer = parse_status(facts.observer_status)?;
        if observer.uids != [0; 4] {
            return Err(anyhow!(
                "hostile-workload oracle mode requires all observer UIDs to be root",
            ));
        }
        let mut uid_map_lines = facts.observer_uid_map.lines();
        let uid_map = uid_map_lines
            .next()
            .ok_or_else(|| anyhow!("observer user namespace has no UID mapping"))?;
        let uid_map = uid_map
            .split_ascii_whitespace()
            .map(str::parse)
            .collect::<Result<Vec<u64>, _>>()
            .map_err(|_| anyhow!("observer user namespace has an invalid UID mapping"))?;
        if uid_map_lines.next().is_some() || uid_map != [0, 0, u64::from(u32::MAX)] {
            return Err(anyhow!(
                "hostile-workload oracle mode requires one full initial-namespace UID mapping"
            ));
        }
        if facts.observer_user_namespace.1 == 0
            || facts.observer_user_namespace != facts.init_user_namespace
        {
            return Err(anyhow!(
                "hostile-workload oracle mode requires the observer and PID 1 user namespaces to match"
            ));
        }
        let target = parse_status(facts.target_status)?;
        validate_target_status(&target)?;
        Ok(())
    })();
    match eligible {
        Ok(()) => Ok(OracleMode::Hardened),
        Err(_) if trusted_workload => Ok(OracleMode::TrustedWorkload),
        Err(error) => Err(trusted_required(error)),
    }
}

pub(crate) fn select(scope: &Scope, trusted_workload: bool) -> Result<OracleSelection> {
    let Scope::Pid(pid) = scope else {
        select_from_facts(scope, trusted_workload, None)?;
        return Ok(OracleSelection::trusted_workload());
    };
    let selected = (|| -> Result<(OracleMode, PinnedTarget)> {
        let target = PinnedTarget::pin(*pid).map_err(|error| {
            trusted_required(format!("pinning observed process {pid} failed: {error}"))
        })?;
        let observer_pid = u32::try_from(unsafe { libc::getpid() })
            .map_err(|_| trusted_required("the observer PID is out of range"))?;
        let observer_directory =
            open_proc_pid_directory(&target.procfs, observer_pid).map_err(|error| {
                trusted_required(format!(
                    "opening the observer proc directory failed: {error}"
                ))
            })?;
        let observer =
            openat_file(&observer_directory, "exe", libc::O_RDONLY).map_err(|error| {
                trusted_required(format!("opening the running observer failed: {error}"))
            })?;
        let metadata = observer.metadata().map_err(|error| {
            trusted_required(format!(
                "reading the running observer metadata failed: {error}"
            ))
        })?;
        let observer_loader = inspect_elf_loader(&observer).map_err(|error| {
            trusted_required(format!("inspecting the running observer failed: {error}"))
        })?;
        let observer_status = read_proc_entry(
            &observer_directory,
            "status",
            MAX_PROC_STATUS_BYTES,
            "observer process status",
        )
        .map_err(|error| {
            trusted_required(format!(
                "reading the observer process status failed: {error}"
            ))
        })?;
        let target_status = target.status().map_err(|error| {
            trusted_required(format!(
                "reading observed process {pid} status failed: {error}"
            ))
        })?;
        let observer_uid_map = read_proc_entry(
            &observer_directory,
            "uid_map",
            MAX_PROC_STATUS_BYTES,
            "observer UID map",
        )
        .map_err(|error| {
            trusted_required(format!("reading the observer UID map failed: {error}"))
        })?;
        let observer_user_namespace = namespace_id_at(&observer_directory).map_err(|error| {
            trusted_required(format!(
                "opening the observer user namespace failed: {error}"
            ))
        })?;
        let init_directory = open_proc_pid_directory(&target.procfs, 1).map_err(|error| {
            trusted_required(format!("opening the PID 1 proc directory failed: {error}"))
        })?;
        let init_user_namespace = namespace_id_at(&init_directory).map_err(|error| {
            trusted_required(format!("opening the PID 1 user namespace failed: {error}"))
        })?;
        let mode = select_from_facts(
            scope,
            false,
            Some(HardenedFacts {
                observer_loader,
                observer_owner: metadata.uid(),
                observer_mode: metadata.mode(),
                observer_status: &observer_status,
                target_status: &target_status,
                observer_uid_map: &observer_uid_map,
                observer_user_namespace,
                init_user_namespace,
            }),
        )?;
        target.revalidate().map_err(|error| {
            trusted_required(format!(
                "revalidating observed process {pid} failed: {error}"
            ))
        })?;
        Ok((mode, target))
    })();
    match selected {
        Ok((OracleMode::Hardened, target)) => Ok(OracleSelection::hardened(target)),
        Ok((OracleMode::TrustedWorkload, _)) => Err(anyhow!(
            "hardened oracle selection unexpectedly returned trusted mode"
        )),
        Err(_) if trusted_workload => Ok(OracleSelection::trusted_workload()),
        Err(error) => Err(error),
    }
}

fn open_pidfd(pid: u32) -> Result<OwnedFd> {
    let pid = libc::pid_t::try_from(pid).map_err(|_| anyhow!("observed PID is out of range"))?;
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as i32;
    if fd == -1 {
        return Err(std::io::Error::last_os_error()).context("opening observed process pidfd");
    }
    normalize_owned_fd(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn ensure_pid_alive(pid: u32, pidfd: &OwnedFd) -> Result<()> {
    let mut pollfd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let result = unsafe { libc::poll(&mut pollfd, 1, 0) };
        if result == 0 {
            return Ok(());
        }
        if result > 0 {
            return Err(anyhow!(
                "observed process {pid} exited while its authority was retained"
            ));
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error).context("checking observed process pidfd");
        }
    }
}

fn open_procfs() -> Result<File> {
    let path = CString::new("/proc").expect("fixed procfs path has no NUL");
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        return Err(std::io::Error::last_os_error()).context("opening /proc");
    }
    let procfs = normalize_file_fd(unsafe { File::from_raw_fd(fd) })?;
    validate_procfs_binding(&procfs)?;
    Ok(procfs)
}

fn validate_procfs(procfs: &File) -> Result<()> {
    let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(procfs.as_raw_fd(), stat.as_mut_ptr()) } == -1 {
        return Err(std::io::Error::last_os_error()).context("identifying /proc filesystem");
    }
    let stat = unsafe { stat.assume_init() };
    if stat.f_type as u64 != libc::PROC_SUPER_MAGIC as u64 {
        return Err(anyhow!("/proc is not a procfs filesystem"));
    }
    Ok(())
}

fn validate_procfs_binding(procfs: &File) -> Result<()> {
    validate_procfs(procfs)?;
    let pid = u32::try_from(unsafe { libc::getpid() })
        .map_err(|_| anyhow!("the observer PID is out of range"))?;
    let self_directory = openat_file(procfs, "self", libc::O_RDONLY | libc::O_DIRECTORY)
        .context("opening procfs self directory")?;
    let numeric_directory = open_proc_pid_directory(procfs, pid)?;
    let status = read_proc_entry(
        &self_directory,
        "status",
        MAX_PROC_STATUS_BYTES,
        "procfs self status",
    )?;
    validate_procfs_binding_facts(
        pid,
        proc_file_identity(&self_directory)?,
        proc_file_identity(&numeric_directory)?,
        &status,
    )
}

fn validate_procfs_binding_facts(
    pid: u32,
    self_identity: ProcFileIdentity,
    numeric_identity: ProcFileIdentity,
    status: &str,
) -> Result<()> {
    if self_identity != numeric_identity {
        return Err(anyhow!(
            "procfs self and numeric observer directory identity differ"
        ));
    }
    let mut nspid = None;
    for line in status.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name != "NSpid" {
            continue;
        }
        if nspid.is_some() {
            return Err(anyhow!("procfs self status has duplicate NSpid fields"));
        }
        let mut values = value.split_ascii_whitespace();
        let value = values
            .next()
            .ok_or_else(|| anyhow!("procfs self status has an empty NSpid field"))?;
        if values.next().is_some() {
            return Err(anyhow!("procfs self status NSpid field is not a singleton"));
        }
        let parsed = value
            .parse::<u32>()
            .map_err(|_| anyhow!("procfs self status has an invalid NSpid field"))?;
        if parsed.to_string() != value || parsed != pid {
            return Err(anyhow!(
                "procfs self status NSpid does not match the observer PID"
            ));
        }
        nspid = Some(parsed);
    }
    nspid
        .map(|_| ())
        .ok_or_else(|| anyhow!("procfs self status is missing its NSpid field"))
}

fn open_proc_pid_directory(procfs: &File, pid: u32) -> Result<File> {
    let name = pid.to_string();
    open_proc_directory(procfs, &name)
        .with_context(|| format!("opening observed process {pid} proc directory"))
}

fn open_proc_directory(parent: &File, name: &str) -> Result<File> {
    let directory = openat_file(
        parent,
        name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
    )?;
    if !directory.metadata()?.is_dir() {
        return Err(anyhow!("proc entry {name:?} is not a directory"));
    }
    Ok(directory)
}

fn open_proc_regular(directory: &File, name: &str) -> Result<File> {
    let file = openat_file(directory, name, libc::O_RDONLY | libc::O_NOFOLLOW)
        .with_context(|| format!("opening observed process proc {name}"))?;
    if !file.metadata()?.is_file() {
        return Err(anyhow!(
            "observed process proc {name} is not a regular file"
        ));
    }
    Ok(file)
}

fn read_proc_entry(directory: &File, name: &str, limit: usize, label: &str) -> Result<String> {
    let file = open_proc_regular(directory, name)?;
    read_proc_text(&file, limit, label)
}

fn namespace_id_at(process_directory: &File) -> Result<(u64, u64)> {
    let namespace_directory = openat_file(
        process_directory,
        "ns",
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
    )?;
    let namespace = openat_file(&namespace_directory, "user", libc::O_RDONLY)?;
    let metadata = namespace.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}

fn openat_file(directory: &File, name: &str, flags: i32) -> Result<File> {
    if name.is_empty() || name.as_bytes().contains(&b'/') {
        return Err(anyhow!("invalid proc entry name"));
    }
    let name = CString::new(name).map_err(|_| anyhow!("proc entry name contains NUL"))?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        return Err(std::io::Error::last_os_error()).context("opening proc entry");
    }
    normalize_file_fd(unsafe { File::from_raw_fd(fd) })
}

fn directory_entry_names(directory: &File, limit: usize, label: &str) -> Result<Vec<OsString>> {
    let directory_fd = directory.as_raw_fd();
    if unsafe { libc::lseek(directory_fd, 0, libc::SEEK_SET) } == -1 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("rewinding {label}"));
    }
    let fd = unsafe { libc::fcntl(directory_fd, libc::F_DUPFD_CLOEXEC, 3) };
    if fd == -1 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("duplicating {label} listing fd"));
    }
    let stream = unsafe { libc::fdopendir(fd) };
    if stream.is_null() {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(error).with_context(|| format!("opening {label} directory stream"));
    }
    let mut entries = Vec::new();
    let result = loop {
        unsafe { *libc::__errno_location() = 0 };
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(0) {
                break Ok(());
            }
            break Err(error).with_context(|| format!("enumerating {label}"));
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name != b"." && name != b".." {
            entries.push(OsString::from_vec(name.to_vec()));
            if entries.len() > limit {
                break Err(anyhow!("{label} exceeds the {limit}-entry limit"));
            }
        }
    };
    let close = unsafe { libc::closedir(stream) };
    let rewind = unsafe { libc::lseek(directory_fd, 0, libc::SEEK_SET) };
    result?;
    if close == -1 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("closing {label} directory stream"));
    }
    if rewind == -1 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("restoring {label} directory offset"));
    }
    Ok(entries)
}

fn proc_file_identity(file: &File) -> Result<ProcFileIdentity> {
    let metadata = file.metadata()?;
    Ok(ProcFileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn target_identity(directory: &File, status: &File, tasks: &File) -> Result<TargetIdentity> {
    let stat = open_proc_regular(directory, "stat")?;
    Ok(TargetIdentity {
        directory: proc_file_identity(directory)?,
        status: proc_file_identity(status)?,
        tasks: proc_file_identity(tasks)?,
        start_time: parse_proc_start_time(&read_proc_bytes(
            &stat,
            MAX_PROC_STAT_BYTES,
            "process stat",
        )?)?,
    })
}

fn validate_task_status(tid: u32, status: &str) -> Result<()> {
    let status = parse_status(status)
        .with_context(|| format!("parsing observed process task {tid} status"))?;
    validate_target_status(&status)
        .with_context(|| format!("observed process task {tid} is not hostile-safe"))
}

fn validated_task_set(tasks: &File, pid: u32) -> Result<TaskIdentitySet> {
    let names = directory_entry_names(tasks, MAX_TARGET_TASKS, "observed process task directory")?;
    let mut identities = BTreeMap::new();
    for name in names {
        let bytes = name.as_bytes();
        if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
            return Err(anyhow!(
                "observed process task directory has a non-TID entry"
            ));
        }
        let tid_text = std::str::from_utf8(bytes)
            .map_err(|_| anyhow!("observed process task directory has a non-UTF-8 TID"))?;
        let tid: u32 = tid_text
            .parse()
            .map_err(|_| anyhow!("observed process task directory has an invalid TID"))?;
        if tid == 0 || tid.to_string() != tid_text {
            return Err(anyhow!(
                "observed process task directory has a non-canonical TID"
            ));
        }
        let directory = open_proc_directory(tasks, tid_text)
            .with_context(|| format!("opening observed process task {tid}"))?;
        let status = open_proc_regular(&directory, "status")
            .with_context(|| format!("opening observed process task {tid} status"))?;
        validate_task_status(
            tid,
            &read_proc_text(
                &status,
                MAX_PROC_STATUS_BYTES,
                "observed process task status",
            )?,
        )?;
        let stat = open_proc_regular(&directory, "stat")?;
        let identity = TaskIdentity {
            directory: proc_file_identity(&directory)?,
            status: proc_file_identity(&status)?,
            start_time: parse_proc_start_time(&read_proc_bytes(
                &stat,
                MAX_PROC_STAT_BYTES,
                "observed process task stat",
            )?)?,
        };
        if identities.insert(tid, identity).is_some() {
            return Err(anyhow!(
                "observed process task directory has duplicate TIDs"
            ));
        }
    }
    if !identities.contains_key(&pid) {
        return Err(anyhow!(
            "observed process task set is missing its leader {pid}"
        ));
    }
    Ok(identities)
}

fn ensure_same_task_set(pid: u32, first: &TaskIdentitySet, second: &TaskIdentitySet) -> Result<()> {
    if first != second {
        return Err(anyhow!(
            "observed process {pid} task set changed during authorization"
        ));
    }
    Ok(())
}

fn ensure_same_target(pid: u32, pinned: TargetIdentity, current: TargetIdentity) -> Result<()> {
    if current != pinned {
        return Err(anyhow!(
            "observed process {pid} proc identity or start time changed (possible PID reuse)"
        ));
    }
    Ok(())
}

fn read_proc_text(file: &File, limit: usize, label: &str) -> Result<String> {
    String::from_utf8(read_proc_bytes(file, limit, label)?)
        .with_context(|| format!("{label} is not UTF-8"))
}

fn read_proc_bytes(file: &File, limit: usize, label: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let read = file
            .read_at(&mut chunk, bytes.len() as u64)
            .with_context(|| format!("reading {label}"))?;
        if read == 0 {
            return Ok(bytes);
        }
        if bytes.len() + read > limit {
            return Err(anyhow!("{label} exceeds the {limit}-byte limit"));
        }
        bytes.extend_from_slice(&chunk[..read]);
    }
}

fn parse_proc_start_time(stat: &[u8]) -> Result<u64> {
    let close = stat
        .iter()
        .rposition(|byte| *byte == b')')
        .ok_or_else(|| anyhow!("process stat is missing its command terminator"))?;
    let start_time = stat[close + 1..]
        .split(u8::is_ascii_whitespace)
        .filter(|field| !field.is_empty())
        .nth(19)
        .ok_or_else(|| anyhow!("process stat is missing its start time"))?;
    std::str::from_utf8(start_time)
        .context("process stat start time is not UTF-8")?
        .parse()
        .context("process stat has an invalid start time")
}

pub(crate) fn normalize_owned_fd(fd: OwnedFd) -> Result<OwnedFd> {
    if fd.as_raw_fd() > 2 {
        return Ok(fd);
    }
    let duplicated = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if duplicated == -1 {
        return Err(std::io::Error::last_os_error()).context("moving authority fd above stdio");
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}

fn prepare_glibc_graph(
    helper: &ElfLoader,
    mut resolve: impl FnMut(&OsStr) -> Result<ElfLoader>,
) -> Result<BTreeMap<OsString, ElfLoader>> {
    if helper.interpreter.as_deref() != Some(Path::new(GLIBC_INTERP)) || helper.soname.is_some() {
        return Err(anyhow!(
            "hardened glibc helper must use the exact supported interpreter and have no SONAME"
        ));
    }
    let mut pending = VecDeque::from([OsString::from(GLIBC_LOADER)]);
    pending.extend(helper.needed.iter().cloned());
    let mut graph = BTreeMap::new();
    while let Some(name) = pending.pop_front() {
        validate_runtime_name(&name)?;
        if graph.contains_key(&name) {
            continue;
        }
        let facts = resolve(&name)?;
        if facts
            .interpreter
            .as_deref()
            .is_some_and(|interpreter| interpreter != Path::new(GLIBC_INTERP))
            || facts.soname.as_deref() != Some(name.as_os_str())
        {
            return Err(anyhow!(
                "runtime object {name:?} has an unexpected interpreter or SONAME"
            ));
        }
        if name == OsStr::new(GLIBC_LOADER)
            && (facts.interpreter.is_some() || !facts.needed.is_empty())
        {
            return Err(anyhow!(
                "the glibc interpreter has an unexpected interpreter or dependencies"
            ));
        }
        for needed in &facts.needed {
            pending.push_back(needed.clone());
        }
        graph.insert(name, facts);
    }
    Ok(graph)
}

fn validate_runtime_name(name: &OsStr) -> Result<()> {
    let bytes = name.as_bytes();
    if bytes.is_empty()
        || bytes == b"."
        || bytes == b".."
        || bytes.contains(&b'/')
        || bytes.contains(&b'$')
        || bytes.contains(&0)
        || !matches!(
            bytes,
            b"ld-linux-x86-64.so.2" | b"libc.so.6" | b"libgcc_s.so.1"
        )
    {
        return Err(anyhow!("unsupported hardened glibc runtime name {name:?}"));
    }
    Ok(())
}

fn unique_runtime_candidate(mut candidates: Vec<std::fs::File>) -> Result<std::fs::File> {
    let selected = candidates
        .pop()
        .ok_or_else(|| anyhow!("required hardened glibc runtime object is unresolved"))?;
    let key = mapping_file_key(&selected).map_err(anyhow::Error::msg)?;
    for candidate in candidates {
        if mapping_file_key(&candidate).map_err(anyhow::Error::msg)? != key {
            return Err(anyhow!(
                "hardened glibc runtime name is ambiguous across distinct inodes"
            ));
        }
    }
    Ok(selected)
}

fn pinned_loader_candidate(
    interpreter: &std::fs::File,
    candidates: Vec<std::fs::File>,
) -> Result<()> {
    if candidates.is_empty() {
        return Err(anyhow!(
            "required hardened glibc loader candidate is unresolved"
        ));
    }
    let interpreter = mapping_file_key(interpreter).map_err(anyhow::Error::msg)?;
    for candidate in candidates {
        if mapping_file_key(&candidate).map_err(anyhow::Error::msg)? != interpreter {
            return Err(anyhow!(
                "a loader search candidate is not the pinned glibc interpreter"
            ));
        }
    }
    Ok(())
}

fn runtime_candidates<'a>(
    directories: impl IntoIterator<Item = &'a File>,
    name: &OsStr,
    owner: u32,
) -> Result<Vec<File>> {
    validate_runtime_name(name)?;
    let mut candidates = Vec::new();
    for directory in directories {
        if let Some(candidate) = open_runtime_candidate(directory, name, owner)? {
            candidates.push(candidate);
        }
    }
    Ok(candidates)
}

fn open_runtime_candidate(directory: &File, name: &OsStr, owner: u32) -> Result<Option<File>> {
    let mut name = name.to_os_string();
    let mut symlink_hops = 0usize;
    loop {
        let c_name = CString::new(name.as_bytes())
            .map_err(|_| anyhow!("runtime candidate name contains NUL"))?;
        let entry = match stat_at(directory, &c_name) {
            Ok(entry) => entry,
            Err(error) if symlink_hops == 0 && error.raw_os_error() == Some(libc::ENOENT) => {
                return Ok(None);
            }
            Err(error) => {
                return Err(error).context("opening hardened glibc runtime candidate");
            }
        };
        if entry.st_mode & libc::S_IFMT == libc::S_IFLNK {
            if entry.st_uid != owner {
                return Err(anyhow!("runtime candidate symlink has an unexpected owner"));
            }
            symlink_hops += 1;
            if symlink_hops > MAX_SYMLINK_HOPS {
                return Err(anyhow!(
                    "runtime candidate exceeds the {MAX_SYMLINK_HOPS}-symlink limit"
                ));
            }
            let target = readlink_at(directory, &c_name)?;
            let target_bytes = target.as_bytes();
            if target_bytes.is_empty()
                || target_bytes == b"."
                || target_bytes == b".."
                || target_bytes.contains(&b'/')
                || target_bytes.contains(&b'$')
                || target_bytes.contains(&0)
            {
                return Err(anyhow!(
                    "runtime candidate has an unsafe same-directory symlink target"
                ));
            }
            let current =
                stat_at(directory, &c_name).context("revalidating runtime candidate symlink")?;
            if !same_stat(&entry, &current) {
                return Err(anyhow!("runtime candidate symlink changed while inspected"));
            }
            name = target;
            continue;
        }
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                c_name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd == -1 {
            return Err(std::io::Error::last_os_error())
                .context("opening hardened glibc runtime candidate");
        }
        let file = normalize_file_fd(unsafe { File::from_raw_fd(fd) })?;
        if !same_stat_file(&entry, &file)? {
            return Err(anyhow!("runtime candidate changed while it was opened"));
        }
        validate_protected_regular(&file, owner, Path::new(&name))?;
        return Ok(Some(file));
    }
}

struct AuthorityRoot {
    root: File,
    owner: u32,
}

#[derive(Clone, Copy)]
enum ExpectedEntry {
    Directory,
    Regular,
    RegularNoSymlink,
}

enum WalkComponent {
    Parent,
    Normal(OsString),
}

impl AuthorityRoot {
    fn open(path: &Path, owner: u32) -> Result<Self> {
        let root = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .with_context(|| format!("opening authority root {}", path.display()))?;
        validate_protected_directory(&root, owner, path)?;
        Ok(Self {
            root: normalize_file_fd(root)?,
            owner,
        })
    }

    fn open_directory(&self, path: &Path, optional: bool) -> Result<Option<File>> {
        self.open_entry(path, optional, ExpectedEntry::Directory)
    }

    fn open_regular(&self, path: &Path, optional: bool) -> Result<Option<File>> {
        self.open_entry(path, optional, ExpectedEntry::Regular)
    }

    fn open_regular_nofollow(&self, path: &Path, optional: bool) -> Result<Option<File>> {
        self.open_entry(path, optional, ExpectedEntry::RegularNoSymlink)
    }

    fn open_entry(
        &self,
        path: &Path,
        optional: bool,
        expected: ExpectedEntry,
    ) -> Result<Option<File>> {
        if !path.is_absolute() {
            return Err(anyhow!("authority path must be absolute"));
        }
        let mut pending = path_components(path)?.1;
        if pending.is_empty() {
            return match expected {
                ExpectedEntry::Directory => Ok(Some(normalize_file_fd(self.root.try_clone()?)?)),
                ExpectedEntry::Regular | ExpectedEntry::RegularNoSymlink => {
                    Err(anyhow!("authority root is not a regular file"))
                }
            };
        }
        let mut directories = vec![normalize_file_fd(self.root.try_clone()?)?];
        let mut symlink_hops = 0usize;
        while let Some(component) = pending.pop_front() {
            if matches!(component, WalkComponent::Parent) {
                if directories.len() == 1 {
                    return Err(anyhow!("authority symlink target escapes its root"));
                }
                directories.pop();
                continue;
            }
            let WalkComponent::Normal(name) = component else {
                unreachable!()
            };
            let name = CString::new(name.as_bytes())
                .map_err(|_| anyhow!("authority path component contains NUL"))?;
            let parent = directories.last().expect("authority root remains retained");
            let entry = match stat_at(parent, &name) {
                Ok(entry) => entry,
                Err(error) if optional && error.raw_os_error() == Some(libc::ENOENT) => {
                    return Ok(None);
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("opening protected authority path {}", path.display())
                    });
                }
            };
            if entry.st_mode & libc::S_IFMT == libc::S_IFLNK {
                if pending.is_empty() && matches!(expected, ExpectedEntry::RegularNoSymlink) {
                    return Err(anyhow!(
                        "authority path {} has a symlink leaf",
                        path.display()
                    ));
                }
                if entry.st_uid != self.owner {
                    return Err(anyhow!(
                        "authority symlink {} is not owned by uid {}",
                        path.display(),
                        self.owner
                    ));
                }
                symlink_hops += 1;
                if symlink_hops > MAX_SYMLINK_HOPS {
                    return Err(anyhow!(
                        "authority path {} exceeds the {MAX_SYMLINK_HOPS}-symlink limit",
                        path.display(),
                    ));
                }
                let target = readlink_at(parent, &name)?;
                let current = stat_at(parent, &name)
                    .context("revalidating authority symlink after readlink")?;
                if !same_stat(&entry, &current) {
                    return Err(anyhow!(
                        "authority symlink {} changed while it was inspected",
                        path.display()
                    ));
                }
                let (absolute, target) = path_components(Path::new(&target))?;
                if target.is_empty() {
                    return Err(anyhow!("authority symlink has an empty target"));
                }
                if absolute {
                    directories.truncate(1);
                }
                for component in target.into_iter().rev() {
                    pending.push_front(component);
                }
                continue;
            }

            let final_component = pending.is_empty();
            let kind = if final_component {
                expected
            } else {
                ExpectedEntry::Directory
            };
            let flags = match kind {
                ExpectedEntry::Directory => libc::O_RDONLY | libc::O_DIRECTORY,
                ExpectedEntry::Regular | ExpectedEntry::RegularNoSymlink => libc::O_RDONLY,
            } | libc::O_NOFOLLOW
                | libc::O_CLOEXEC;
            let fd = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
            if fd == -1 {
                let error = std::io::Error::last_os_error();
                if optional && error.raw_os_error() == Some(libc::ENOENT) {
                    return Ok(None);
                }
                return Err(error).with_context(|| {
                    format!("opening protected authority path {}", path.display())
                });
            }
            let opened = normalize_file_fd(unsafe { File::from_raw_fd(fd) })?;
            if !same_stat_file(&entry, &opened)? {
                return Err(anyhow!(
                    "authority path {} changed while it was opened",
                    path.display()
                ));
            }
            match kind {
                ExpectedEntry::Directory => {
                    validate_protected_directory(&opened, self.owner, path)?;
                    if final_component {
                        return Ok(Some(opened));
                    }
                    directories.push(opened);
                }
                ExpectedEntry::Regular | ExpectedEntry::RegularNoSymlink => {
                    validate_protected_regular(&opened, self.owner, path)?;
                    return Ok(Some(opened));
                }
            }
        }
        Err(anyhow!("authority path did not resolve to an entry"))
    }
}

fn path_components(path: &Path) -> Result<(bool, VecDeque<WalkComponent>)> {
    let mut absolute = false;
    let mut components = VecDeque::new();
    for component in path.components() {
        match component {
            Component::RootDir => absolute = true,
            Component::CurDir => {}
            Component::ParentDir => components.push_back(WalkComponent::Parent),
            Component::Normal(name) => {
                components.push_back(WalkComponent::Normal(name.to_os_string()));
            }
            Component::Prefix(_) => {
                return Err(anyhow!("authority path has an unsupported prefix"));
            }
        }
    }
    Ok((absolute, components))
}

fn stat_at(parent: &File, name: &CString) -> std::io::Result<libc::stat> {
    loop {
        let mut stat = std::mem::MaybeUninit::uninit();
        if unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != -1
        {
            return Ok(unsafe { stat.assume_init() });
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn readlink_at(parent: &File, name: &CString) -> Result<OsString> {
    let mut bytes = [0u8; 4096];
    let length = unsafe {
        libc::readlinkat(
            parent.as_raw_fd(),
            name.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if length == -1 {
        return Err(std::io::Error::last_os_error()).context("reading authority symlink");
    }
    let length = usize::try_from(length).map_err(|_| anyhow!("invalid symlink length"))?;
    if length == bytes.len() {
        return Err(anyhow!("authority symlink target is too long"));
    }
    Ok(OsStr::from_bytes(&bytes[..length]).to_os_string())
}

fn same_stat(left: &libc::stat, right: &libc::stat) -> bool {
    left.st_dev == right.st_dev
        && left.st_ino == right.st_ino
        && left.st_mode & libc::S_IFMT == right.st_mode & libc::S_IFMT
}

fn same_stat_file(entry: &libc::stat, file: &File) -> Result<bool> {
    let metadata = file.metadata()?;
    Ok(entry.st_dev == metadata.dev()
        && entry.st_ino == metadata.ino()
        && entry.st_mode & libc::S_IFMT == metadata.mode() & libc::S_IFMT)
}

#[derive(Debug)]
enum PreloadState {
    Absent {
        etc: File,
    },
    Empty {
        etc: File,
        preload: File,
        owner: u32,
    },
}

impl PreloadState {
    fn capture(
        authority: &AuthorityRoot,
        mut retain: impl FnMut(&File) -> Result<()>,
    ) -> Result<Self> {
        let etc = authority
            .open_directory(Path::new("/etc"), false)?
            .ok_or_else(|| anyhow!("protected /etc directory is absent"))?;
        let Some(preload) = open_preload_entry(&etc)? else {
            return Ok(Self::Absent { etc });
        };
        validate_protected_regular(&preload, authority.owner, Path::new("/etc/ld.so.preload"))?;
        retain(&preload)?;
        revalidate_preload_entry(&etc, &preload, authority.owner)?;
        validate_empty_file(&preload)?;
        Ok(Self::Empty {
            etc,
            preload,
            owner: authority.owner,
        })
    }

    #[cfg(test)]
    fn is_absent(&self) -> bool {
        matches!(self, Self::Absent { .. })
    }

    fn etc(&self) -> &File {
        match self {
            Self::Absent { etc } | Self::Empty { etc, .. } => etc,
        }
    }

    fn revalidate(&self) -> Result<()> {
        match self {
            Self::Absent { etc } => {
                if open_preload_entry(etc)?.is_some() {
                    return Err(anyhow!("/etc/ld.so.preload appeared after preparation"));
                }
                Ok(())
            }
            Self::Empty {
                etc,
                preload,
                owner,
            } => {
                revalidate_preload_entry(etc, preload, *owner)?;
                validate_empty_file(preload)
            }
        }
    }
}

#[derive(Debug)]
struct AliasExpectation {
    link_text: OsString,
    target: MappingFileKey,
}

struct PrivateAliasDir {
    parent: File,
    name: OsString,
    directory: Option<File>,
    child_identity: Option<(u64, u64)>,
    owner: u32,
    aliases: BTreeMap<OsString, AliasExpectation>,
    ready: bool,
    cleaned: bool,
}

impl PrivateAliasDir {
    fn create(parent: &File, owner: u32, aliases: Vec<(OsString, &File)>) -> Result<Self> {
        validate_protected_directory(parent, owner, Path::new("private alias parent"))?;
        let parent = normalize_file_fd(parent.try_clone()?)?;
        for _ in 0..128 {
            let name = random_alias_directory_name()?;
            let c_name = CString::new(name.as_bytes()).expect("generated alias directory name");
            if unsafe { libc::mkdirat(parent.as_raw_fd(), c_name.as_ptr(), 0o700) } == -1 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EEXIST) {
                    continue;
                }
                return Err(error).context("creating private glibc alias directory");
            }
            let mut private = Self {
                parent,
                name,
                directory: None,
                child_identity: None,
                owner,
                aliases: BTreeMap::new(),
                ready: false,
                cleaned: false,
            };
            let initialized = private.initialize(aliases);
            if let Err(error) = initialized {
                return match private.cleanup() {
                    Ok(()) => Err(error),
                    Err(cleanup) => Err(anyhow!(
                        "{error:#}; private alias cleanup also failed: {cleanup:#}"
                    )),
                };
            }
            return Ok(private);
        }
        Err(anyhow!(
            "could not allocate a unique private glibc alias directory"
        ))
    }

    fn initialize(&mut self, aliases: Vec<(OsString, &File)>) -> Result<()> {
        let name = CString::new(self.name.as_bytes()).expect("generated alias directory name");
        let entry = stat_at(&self.parent, &name)
            .context("pinning newly created private glibc alias directory")?;
        self.child_identity = Some((entry.st_dev, entry.st_ino));
        let directory = open_child_directory(&self.parent, &name)?;
        if !same_stat_file(&entry, &directory)? {
            return Err(anyhow!("private glibc alias directory changed after mkdir"));
        }
        self.directory = Some(directory);
        for (alias, target) in aliases {
            validate_runtime_name(&alias)?;
            if target.as_raw_fd() <= 2 {
                return Err(anyhow!("private glibc alias target fd is not above stdio"));
            }
            if self.aliases.contains_key(&alias) {
                return Err(anyhow!("duplicate private glibc alias {alias:?}"));
            }
            let target_key = mapping_file_key(target).map_err(anyhow::Error::msg)?;
            let link_text = OsString::from(format!("/proc/self/fd/{}", target.as_raw_fd()));
            let c_link = CString::new(link_text.as_bytes()).expect("numeric proc fd alias target");
            let c_alias = CString::new(alias.as_bytes())
                .map_err(|_| anyhow!("private glibc alias contains NUL"))?;
            if unsafe { libc::symlinkat(c_link.as_ptr(), self.directory_fd(), c_alias.as_ptr()) }
                == -1
            {
                return Err(std::io::Error::last_os_error())
                    .context("creating private glibc fd alias");
            }
            self.aliases.insert(
                alias,
                AliasExpectation {
                    link_text,
                    target: target_key,
                },
            );
        }
        if unsafe { libc::fchmod(self.directory_fd(), 0o511) } == -1 {
            return Err(std::io::Error::last_os_error())
                .context("protecting private glibc alias directory");
        }
        self.ready = true;
        self.revalidate()
    }

    #[cfg(test)]
    fn name(&self) -> &OsStr {
        &self.name
    }

    fn directory_fd(&self) -> i32 {
        self.directory
            .as_ref()
            .expect("private alias directory is initialized")
            .as_raw_fd()
    }

    fn validate_child(&self, require_ready_mode: bool) -> Result<()> {
        validate_protected_directory(&self.parent, self.owner, Path::new("private alias parent"))?;
        let expected = self
            .child_identity
            .ok_or_else(|| anyhow!("private alias child identity was never pinned"))?;
        let name = CString::new(self.name.as_bytes()).expect("generated alias directory name");
        let entry = stat_at(&self.parent, &name)
            .context("revalidating private glibc alias directory entry")?;
        if (entry.st_dev, entry.st_ino) != expected {
            return Err(anyhow!("private glibc alias child entry was replaced"));
        }
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| anyhow!("private glibc alias directory fd is missing"))?;
        if !same_stat_file(&entry, directory)? {
            return Err(anyhow!("private glibc alias child fd was replaced"));
        }
        let metadata = directory.metadata()?;
        let mode = metadata.mode() & 0o7777;
        let valid_mode = if require_ready_mode {
            mode == 0o511
        } else {
            matches!(mode, 0o511 | 0o700)
        };
        if !metadata.is_dir() || metadata.uid() != self.owner || !valid_mode {
            return Err(anyhow!(
                "private glibc alias directory has unexpected owner or mode"
            ));
        }
        Ok(())
    }

    fn recover_child_fd(&mut self) -> Result<()> {
        if self.directory.is_some() {
            return Ok(());
        }
        validate_protected_directory(&self.parent, self.owner, Path::new("private alias parent"))?;
        let expected = self
            .child_identity
            .ok_or_else(|| anyhow!("private alias child identity was never pinned"))?;
        let name = CString::new(self.name.as_bytes()).expect("generated alias directory name");
        let entry = stat_at(&self.parent, &name)
            .context("recovering private glibc alias directory entry")?;
        if (entry.st_dev, entry.st_ino) != expected
            || entry.st_mode & libc::S_IFMT != libc::S_IFDIR
            || entry.st_uid != self.owner
        {
            return Err(anyhow!(
                "private glibc alias child entry cannot be safely recovered"
            ));
        }
        if self.directory.is_none() {
            let directory = open_child_directory(&self.parent, &name)?;
            if !same_stat_file(&entry, &directory)? {
                return Err(anyhow!("recovered private alias authority fd changed"));
            }
            self.directory = Some(directory);
        }
        Ok(())
    }

    fn entries(&self) -> Result<BTreeSet<OsString>> {
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| anyhow!("private glibc alias directory fd is missing"))?;
        Ok(directory_entry_names(
            directory,
            self.aliases.len().saturating_add(1),
            "private glibc alias directory",
        )?
        .into_iter()
        .collect())
    }

    fn validate_aliases(&self) -> Result<()> {
        let entries = self.entries()?;
        let expected = self.aliases.keys().cloned().collect::<BTreeSet<_>>();
        if entries != expected {
            return Err(anyhow!("private glibc alias entry set changed"));
        }
        let directory = self
            .directory
            .as_ref()
            .ok_or_else(|| anyhow!("private glibc alias directory fd is missing"))?;
        for (name, expected) in &self.aliases {
            let c_name = CString::new(name.as_bytes())
                .map_err(|_| anyhow!("private glibc alias contains NUL"))?;
            let entry = stat_at(directory, &c_name)?;
            if entry.st_mode & libc::S_IFMT != libc::S_IFLNK || entry.st_uid != self.owner {
                return Err(anyhow!(
                    "private glibc alias {name:?} changed type or owner"
                ));
            }
            let link = readlink_at(directory, &c_name)?;
            let current = stat_at(directory, &c_name)?;
            if !same_stat(&entry, &current) || link != expected.link_text {
                return Err(anyhow!("private glibc alias {name:?} was retargeted"));
            }
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    c_name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC,
                )
            };
            if fd == -1 {
                return Err(std::io::Error::last_os_error())
                    .context("following private glibc fd alias");
            }
            let followed = normalize_file_fd(unsafe { File::from_raw_fd(fd) })?;
            if mapping_file_key(&followed).map_err(anyhow::Error::msg)? != expected.target {
                return Err(anyhow!("private glibc alias {name:?} target changed"));
            }
        }
        Ok(())
    }

    fn revalidate(&self) -> Result<()> {
        self.validate_child(true)?;
        self.validate_aliases()
    }

    fn unlink_aliases(
        &mut self,
        mut unlink: impl FnMut(i32, &CStr) -> std::io::Result<()>,
    ) -> std::io::Result<()> {
        let directory = self.directory_fd();
        let names = self.aliases.keys().cloned().collect::<Vec<_>>();
        for name in names {
            let c_name = CString::new(name.as_bytes()).expect("validated glibc alias name");
            unlink(directory, &c_name)?;
            self.aliases.remove(&name);
        }
        Ok(())
    }

    fn cleanup(&mut self) -> Result<()> {
        if self.cleaned {
            return Ok(());
        }
        self.recover_child_fd()?;
        self.validate_child(self.ready)?;
        self.validate_aliases()?;
        if unsafe { libc::fchmod(self.directory_fd(), 0o700) } == -1 {
            return Err(std::io::Error::last_os_error())
                .context("opening private glibc alias directory for cleanup");
        }
        self.ready = false;
        self.unlink_aliases(|directory, name| {
            if unsafe { libc::unlinkat(directory, name.as_ptr(), 0) } == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        })
        .context("removing private glibc fd alias")?;
        if !self.entries()?.is_empty() {
            return Err(anyhow!(
                "private glibc alias directory was not empty after cleanup"
            ));
        }
        self.validate_child(false)?;
        let name = CString::new(self.name.as_bytes()).expect("generated alias directory name");
        if unsafe { libc::unlinkat(self.parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) }
            == -1
        {
            return Err(std::io::Error::last_os_error())
                .context("removing private glibc alias directory");
        }
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for PrivateAliasDir {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.cleanup();
        }
    }
}

fn random_alias_directory_name() -> Result<OsString> {
    let mut random = [0u8; 16];
    let mut filled = 0usize;
    while filled < random.len() {
        let read = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                random[filled..].as_mut_ptr(),
                random.len() - filled,
                0,
            )
        };
        if read == -1 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error).context("generating private glibc alias directory name");
        }
        if read == 0 {
            return Err(anyhow!(
                "getrandom returned EOF for private glibc alias directory name"
            ));
        }
        filled += usize::try_from(read).map_err(|_| anyhow!("invalid getrandom length"))?;
    }
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(7 + random.len() * 2);
    name.push_str("oracle-");
    for byte in random {
        name.push(char::from(HEX[usize::from(byte >> 4)]));
        name.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    Ok(OsString::from(name))
}

fn open_child_directory(parent: &File, name: &CStr) -> Result<File> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        return Err(std::io::Error::last_os_error())
            .context("opening private glibc alias directory");
    }
    normalize_file_fd(unsafe { File::from_raw_fd(fd) })
}

enum FixedDirectory {
    Absent { path: &'static str },
    Present { path: &'static str, file: File },
}

impl FixedDirectory {
    fn capture(authority: &AuthorityRoot, path: &'static str) -> Result<Self> {
        Ok(match authority.open_directory(Path::new(path), true)? {
            Some(file) => Self::Present { path, file },
            None => Self::Absent { path },
        })
    }

    fn file(&self) -> Option<&File> {
        match self {
            Self::Absent { .. } => None,
            Self::Present { file, .. } => Some(file),
        }
    }

    fn revalidate(&self, authority: &AuthorityRoot) -> Result<()> {
        match self {
            Self::Absent { path } => {
                if authority.open_directory(Path::new(path), true)?.is_some() {
                    return Err(anyhow!(
                        "hardened glibc search directory {path} appeared after preparation"
                    ));
                }
            }
            Self::Present { path, file } => {
                let current = authority
                    .open_directory(Path::new(path), false)?
                    .ok_or_else(|| anyhow!("hardened glibc search directory {path} vanished"))?;
                require_same_mapping(&current, file, "hardened glibc search directory")?;
            }
        }
        Ok(())
    }
}

pub(crate) struct PreparedGlibc<'a> {
    // This guard must clean its child before any retained path or lease can drop.
    private: PrivateAliasDir,
    leases: &'a mut crate::discover_cmd::ClosureLeases,
    authority: AuthorityRoot,
    helper_path: PathBuf,
    helper_fd: RawFd,
    runtime_fds: BTreeMap<OsString, RawFd>,
    search_directories: Vec<FixedDirectory>,
    preload: PreloadState,
    staging_parent: File,
    owner: u32,
}

impl PreparedGlibc<'_> {
    pub(crate) fn revalidate(&self) -> Result<()> {
        revalidate_glibc_pins(
            &self.authority,
            &self.helper_path,
            self.helper_fd,
            &self.runtime_fds,
            &self.search_directories,
            &self.preload,
            &self.staging_parent,
            self.owner,
            self.leases,
        )?;
        self.private.revalidate()
    }

    #[allow(dead_code, reason = "polled by the hardened child supervisor in C3.3")]
    pub(crate) fn lease_event_fd(&self) -> BorrowedFd<'_> {
        self.leases.event_fd()
    }

    #[allow(dead_code, reason = "polled by the hardened child supervisor in C3.3")]
    pub(crate) fn take_lease_break(&self) -> Result<bool, String> {
        self.leases.take_break()
    }

    pub(crate) fn stabilization_keys(&self) -> Result<BTreeSet<MappingFileKey>> {
        self.leases.stabilization_keys()
    }

    pub(crate) fn seed_key(&self) -> MappingFileKey {
        self.leases.seed_key()
    }

    pub(crate) fn retain_reported_nonexiting(&mut self, record: &ProvenanceObject) -> Result<bool> {
        self.leases.retain_reported_nonexiting(record)
    }

    pub(crate) fn helper_fd(&self) -> RawFd {
        self.helper_fd
    }

    pub(crate) fn loader_fd(&self) -> Result<RawFd> {
        self.runtime_fds
            .get(OsStr::new(GLIBC_LOADER))
            .copied()
            .ok_or_else(|| anyhow!("pinned hardened glibc interpreter fd is missing"))
    }

    pub(crate) fn private_directory_fd(&self) -> RawFd {
        self.private.directory_fd()
    }

    pub(crate) fn runtime_fds(&self) -> impl Iterator<Item = RawFd> + '_ {
        self.runtime_fds.values().copied()
    }

    #[allow(dead_code, reason = "private one-pass seam awaiting C3.3B wiring")]
    pub(crate) fn file_key(&self, fd: RawFd) -> Result<MappingFileKey> {
        mapping_file_key(
            self.leases
                .file(fd)
                .ok_or_else(|| anyhow!("retained hardened glibc fd {fd} is missing"))?,
        )
        .map_err(anyhow::Error::msg)
    }

    #[allow(dead_code, reason = "private one-pass seam awaiting C3.3B wiring")]
    pub(crate) fn revalidate_seed(&self, module: &Path) -> Result<()> {
        self.leases.revalidate_seed(module)
    }

    pub(crate) fn alias_links(&self) -> impl Iterator<Item = (&OsStr, &OsStr)> {
        self.private
            .aliases
            .iter()
            .map(|(name, expected)| (name.as_os_str(), expected.link_text.as_os_str()))
    }

    pub(crate) fn cleanup(&mut self) -> Result<()> {
        self.private.cleanup()
    }
}

pub(crate) fn prepare_glibc<'a>(
    helper: File,
    helper_path: &Path,
    leases: &'a mut crate::discover_cmd::ClosureLeases,
) -> Result<PreparedGlibc<'a>> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(anyhow!(
            "hardened glibc preparation requires effective host uid 0"
        ));
    }
    let authority = AuthorityRoot::open(Path::new("/"), 0)?;
    prepare_glibc_in_root(authority, helper, helper_path, 0, leases)
}

#[cfg(test)]
pub(crate) fn prepare_glibc_test_root<'a>(
    root: &Path,
    helper_path: &Path,
    owner: u32,
    leases: &'a mut crate::discover_cmd::ClosureLeases,
) -> Result<PreparedGlibc<'a>> {
    let authority = AuthorityRoot::open(root, owner)?;
    let helper = authority
        .open_regular_nofollow(helper_path, false)?
        .ok_or_else(|| anyhow!("hardened glibc helper is absent"))?;
    prepare_glibc_in_root(authority, helper, helper_path, owner, leases)
}

fn prepare_glibc_in_root<'a>(
    authority: AuthorityRoot,
    helper: File,
    helper_path: &Path,
    owner: u32,
    leases: &'a mut crate::discover_cmd::ClosureLeases,
) -> Result<PreparedGlibc<'a>> {
    validate_hardened_helper(&helper, owner)?;
    let current_helper = authority
        .open_regular_nofollow(helper_path, false)?
        .ok_or_else(|| anyhow!("hardened glibc helper is absent"))?;
    require_same_mapping(&current_helper, &helper, "hardened glibc helper")?;
    let helper_fd = leases.retain_influence(helper, "hardened glibc helper")?;
    let helper_facts = inspect_elf_loader(
        leases
            .file(helper_fd)
            .ok_or_else(|| anyhow!("retained hardened glibc helper fd is missing"))?,
    )
    .map_err(anyhow::Error::msg)
    .context("inspecting hardened glibc helper")?;
    let interpreter = authority
        .open_regular(Path::new(GLIBC_INTERP), false)?
        .ok_or_else(|| anyhow!("hardened glibc interpreter is absent"))?;
    let interpreter_fd = leases.retain_influence(interpreter, "hardened glibc interpreter")?;
    let search_directories = GLIBC_SEARCH_DIRECTORIES
        .into_iter()
        .map(|path| FixedDirectory::capture(&authority, path))
        .collect::<Result<Vec<_>>>()?;
    let search_files = search_directories
        .iter()
        .filter_map(FixedDirectory::file)
        .collect::<Vec<_>>();
    let mut runtime_fds = BTreeMap::new();
    let _graph = prepare_glibc_graph(&helper_facts, |name| {
        let candidates = runtime_candidates(search_files.iter().copied(), name, owner)?;
        let (fd, facts) = if name == OsStr::new(GLIBC_LOADER) {
            let interpreter = leases
                .file(interpreter_fd)
                .ok_or_else(|| anyhow!("retained hardened glibc interpreter fd is missing"))?;
            pinned_loader_candidate(interpreter, candidates)?;
            let facts = inspect_elf_loader(interpreter)
                .map_err(anyhow::Error::msg)
                .context("inspecting retained hardened glibc interpreter")?;
            (interpreter_fd, facts)
        } else {
            let file = unique_runtime_candidate(candidates)?;
            let fd = leases.retain_influence(file, &format!("hardened glibc runtime {name:?}"))?;
            let facts = inspect_elf_loader(
                leases
                    .file(fd)
                    .ok_or_else(|| anyhow!("retained hardened glibc runtime fd is missing"))?,
            )
            .map_err(anyhow::Error::msg)
            .with_context(|| format!("inspecting hardened glibc runtime {name:?}"))?;
            (fd, facts)
        };
        runtime_fds.insert(name.to_os_string(), fd);
        Ok(facts)
    })?;
    let preload = PreloadState::capture(&authority, |file| {
        leases
            .retain_influence(file.try_clone()?, "/etc/ld.so.preload")
            .map(|_| ())
    })?;
    let staging_parent = open_or_create_staging_parent(&authority, owner)?;

    leases.ensure().map_err(anyhow::Error::msg)?;
    revalidate_glibc_pins(
        &authority,
        helper_path,
        helper_fd,
        &runtime_fds,
        &search_directories,
        &preload,
        &staging_parent,
        owner,
        leases,
    )?;
    leases.ensure().map_err(anyhow::Error::msg)?;

    let aliases = runtime_fds
        .iter()
        .map(|(name, fd)| {
            let file = leases
                .file(*fd)
                .ok_or_else(|| anyhow!("retained hardened glibc runtime fd is missing"))?;
            Ok((name.clone(), file))
        })
        .collect::<Result<Vec<_>>>()?;
    let private = PrivateAliasDir::create(&staging_parent, owner, aliases)?;
    Ok(PreparedGlibc {
        private,
        leases,
        authority,
        helper_path: helper_path.to_path_buf(),
        helper_fd,
        runtime_fds,
        search_directories,
        preload,
        staging_parent,
        owner,
    })
}

fn validate_hardened_helper(helper: &File, owner: u32) -> Result<()> {
    validate_protected_regular(helper, owner, Path::new("hardened glibc helper"))?;
    if helper.metadata()?.mode() & 0o111 == 0 {
        return Err(anyhow!("hardened glibc helper is not executable"));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn revalidate_glibc_pins(
    authority: &AuthorityRoot,
    helper_path: &Path,
    helper_fd: RawFd,
    runtime_fds: &BTreeMap<OsString, RawFd>,
    search_directories: &[FixedDirectory],
    preload: &PreloadState,
    staging_parent: &File,
    owner: u32,
    leases: &crate::discover_cmd::ClosureLeases,
) -> Result<()> {
    let retained_helper = leases
        .file(helper_fd)
        .ok_or_else(|| anyhow!("retained hardened glibc helper fd is missing"))?;
    let current_helper = authority
        .open_regular_nofollow(helper_path, false)?
        .ok_or_else(|| anyhow!("hardened glibc helper vanished"))?;
    require_same_mapping(&current_helper, retained_helper, "hardened glibc helper")?;
    for directory in search_directories {
        directory.revalidate(authority)?;
    }
    let current_staging = authority
        .open_directory(Path::new(GLIBC_STAGING_DIRECTORY), false)?
        .ok_or_else(|| anyhow!("protected {GLIBC_STAGING_DIRECTORY} vanished"))?;
    validate_staging_parent(&current_staging, owner)?;
    require_same_mapping(
        &current_staging,
        staging_parent,
        "private glibc staging parent",
    )?;
    let current_etc = authority
        .open_directory(Path::new("/etc"), false)?
        .ok_or_else(|| anyhow!("protected /etc vanished"))?;
    require_same_mapping(&current_etc, preload.etc(), "protected /etc")?;
    preload.revalidate()?;

    let loader_fd = runtime_fds
        .get(OsStr::new(GLIBC_LOADER))
        .ok_or_else(|| anyhow!("pinned hardened glibc interpreter fd is missing"))?;
    let retained_interpreter = leases
        .file(*loader_fd)
        .ok_or_else(|| anyhow!("retained hardened glibc interpreter fd is missing"))?;
    let current_interpreter = authority
        .open_regular(Path::new(GLIBC_INTERP), false)?
        .ok_or_else(|| anyhow!("hardened glibc interpreter vanished"))?;
    require_same_mapping(
        &current_interpreter,
        retained_interpreter,
        "hardened glibc interpreter",
    )?;

    let search_files = search_directories
        .iter()
        .filter_map(FixedDirectory::file)
        .collect::<Vec<_>>();
    for (name, fd) in runtime_fds {
        let retained = leases
            .file(*fd)
            .ok_or_else(|| anyhow!("retained hardened glibc runtime fd is missing"))?;
        let candidates = runtime_candidates(search_files.iter().copied(), name, owner)?;
        if name == OsStr::new(GLIBC_LOADER) {
            pinned_loader_candidate(retained, candidates)?;
        } else {
            let current = unique_runtime_candidate(candidates)?;
            require_same_mapping(&current, retained, "hardened glibc runtime candidate")?;
        }
    }

    let helper_facts = inspect_elf_loader(retained_helper)
        .map_err(anyhow::Error::msg)
        .context("revalidating hardened glibc helper facts")?;
    let graph = prepare_glibc_graph(&helper_facts, |name| {
        let fd = runtime_fds
            .get(name)
            .ok_or_else(|| anyhow!("hardened glibc graph gained an unresolved object"))?;
        inspect_elf_loader(
            leases
                .file(*fd)
                .ok_or_else(|| anyhow!("retained hardened glibc runtime fd is missing"))?,
        )
        .map_err(anyhow::Error::msg)
    })?;
    if graph.keys().ne(runtime_fds.keys()) {
        return Err(anyhow!(
            "hardened glibc runtime graph changed after preparation"
        ));
    }
    Ok(())
}

fn validate_staging_parent(parent: &File, owner: u32) -> Result<()> {
    let metadata = parent.metadata()?;
    if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o7777 != 0o755 {
        return Err(anyhow!(
            "{GLIBC_STAGING_DIRECTORY} must be an owner-controlled mode-0755 directory"
        ));
    }
    Ok(())
}

fn open_or_create_staging_parent(authority: &AuthorityRoot, owner: u32) -> Result<File> {
    if let Some(parent) = authority.open_directory(Path::new(GLIBC_STAGING_DIRECTORY), true)? {
        validate_staging_parent(&parent, owner)?;
        return Ok(parent);
    }
    let run = authority
        .open_directory(Path::new("/run"), false)?
        .ok_or_else(|| anyhow!("protected /run is absent"))?;
    let name = c"p11scope";
    if unsafe { libc::mkdirat(run.as_raw_fd(), name.as_ptr(), 0o755) } == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EEXIST) {
            return Err(error).context("creating protected /run/p11scope");
        }
        let parent = authority
            .open_directory(Path::new(GLIBC_STAGING_DIRECTORY), false)?
            .ok_or_else(|| anyhow!("raced /run/p11scope creation vanished"))?;
        validate_staging_parent(&parent, owner)?;
        return Ok(parent);
    }
    let created = open_child_directory(&run, name)?;
    if unsafe { libc::fchmod(created.as_raw_fd(), 0o755) } == -1 {
        return Err(std::io::Error::last_os_error())
            .context("setting protected /run/p11scope mode");
    }
    validate_staging_parent(&created, owner)?;
    let current = authority
        .open_directory(Path::new(GLIBC_STAGING_DIRECTORY), false)?
        .ok_or_else(|| anyhow!("new /run/p11scope vanished"))?;
    require_same_mapping(&current, &created, "new /run/p11scope")?;
    Ok(created)
}

fn require_same_mapping(current: &File, retained: &File, label: &str) -> Result<()> {
    if mapping_file_key(current).map_err(anyhow::Error::msg)?
        != mapping_file_key(retained).map_err(anyhow::Error::msg)?
    {
        return Err(anyhow!("{label} changed after preparation"));
    }
    Ok(())
}

fn open_preload_entry(etc: &File) -> Result<Option<File>> {
    let name = c"ld.so.preload";
    let fd = unsafe {
        libc::openat(
            etc.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(error).context("opening protected /etc/ld.so.preload entry");
    }
    normalize_file_fd(unsafe { File::from_raw_fd(fd) }).map(Some)
}

fn revalidate_preload_entry(etc: &File, preload: &File, owner: u32) -> Result<()> {
    let current = open_preload_entry(etc)?
        .ok_or_else(|| anyhow!("/etc/ld.so.preload changed after preparation"))?;
    if mapping_file_key(&current).map_err(anyhow::Error::msg)?
        != mapping_file_key(preload).map_err(anyhow::Error::msg)?
    {
        return Err(anyhow!("/etc/ld.so.preload changed after preparation"));
    }
    validate_protected_regular(&current, owner, Path::new("/etc/ld.so.preload"))
}

fn validate_protected_regular(file: &File, owner: u32, path: &Path) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != owner || metadata.mode() & 0o022 != 0 {
        return Err(anyhow!(
            "authority file {} is not protected (uid {}, mode {:#o})",
            path.display(),
            metadata.uid(),
            metadata.mode() & 0o7777
        ));
    }
    Ok(())
}

fn validate_empty_file(file: &File) -> Result<()> {
    if file.metadata()?.len() != 0 {
        return Err(anyhow!("/etc/ld.so.preload is not empty"));
    }
    let mut byte = [0u8; 1];
    if file.read_at(&mut byte, 0)? != 0 {
        return Err(anyhow!("/etc/ld.so.preload is not empty"));
    }
    Ok(())
}

fn validate_protected_directory(file: &File, owner: u32, path: &Path) -> Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_dir() || metadata.uid() != owner || metadata.mode() & 0o022 != 0 {
        return Err(anyhow!(
            "authority directory {} is not protected (uid {}, mode {:#o})",
            path.display(),
            metadata.uid(),
            metadata.mode() & 0o7777
        ));
    }
    Ok(())
}

fn normalize_file_fd(file: File) -> Result<File> {
    if file.as_raw_fd() > 2 {
        return Ok(file);
    }
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if fd == -1 {
        return Err(std::io::Error::last_os_error()).context("moving authority fd above stdio");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn parse_status(status: &str) -> Result<ProcessStatus> {
    let mut uids = None;
    let mut capabilities = 0u64;
    let mut seen_caps = 0u8;
    let mut no_new_privileges = None;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("Uid:") {
            if uids.is_some() {
                return Err(anyhow!("process status contains duplicate Uid fields"));
            }
            let values = value
                .split_ascii_whitespace()
                .map(str::parse)
                .collect::<Result<Vec<u32>, _>>()
                .map_err(|_| anyhow!("process status contains an invalid Uid field"))?;
            uids = Some(
                values
                    .try_into()
                    .map_err(|_| anyhow!("process status Uid field must contain four values"))?,
            );
            continue;
        }
        for (index, name) in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"]
            .into_iter()
            .enumerate()
        {
            let Some(value) = line.strip_prefix(name) else {
                continue;
            };
            let bit = 1u8 << index;
            if seen_caps & bit != 0 {
                return Err(anyhow!("process status contains duplicate {name} fields"));
            }
            seen_caps |= bit;
            capabilities |= u64::from_str_radix(value.trim(), 16)
                .map_err(|_| anyhow!("process status contains an invalid {name} field"))?;
        }
        if let Some(value) = line.strip_prefix("NoNewPrivs:") {
            if no_new_privileges.is_some() {
                return Err(anyhow!(
                    "process status contains duplicate NoNewPrivs fields"
                ));
            }
            no_new_privileges = Some(match value.trim() {
                "0" => false,
                "1" => true,
                _ => {
                    return Err(anyhow!(
                        "process status contains an invalid NoNewPrivs field"
                    ));
                }
            });
        }
    }
    if seen_caps != 0b1111 {
        return Err(anyhow!("process status is missing capability fields"));
    }
    Ok(ProcessStatus {
        uids: uids.ok_or_else(|| anyhow!("process status is missing its Uid field"))?,
        capabilities,
        no_new_privileges: no_new_privileges
            .ok_or_else(|| anyhow!("process status is missing its NoNewPrivs field"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attach::Scope;
    use p11scope_manifest::identity::ElfLoader;
    use std::ffi::OsString;
    use std::os::unix::fs::PermissionsExt as _;
    use std::os::unix::process::CommandExt as _;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    const ROOT_STATUS: &str = "Uid:\t0\t0\t0\t0\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t0\n";
    const TARGET_STATUS: &str = "Uid:\t1000\t1000\t1000\t1000\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\n";
    const FULL_UID_MAP: &str = "         0          0 4294967295\n";

    fn static_loader() -> ElfLoader {
        ElfLoader {
            interpreter: None,
            needed: vec![],
            soname: None,
        }
    }

    fn configure_non_root_no_new_privileges(command: &mut Command) {
        unsafe {
            command.pre_exec(|| {
                if libc::geteuid() == 0
                    && (libc::setgroups(0, std::ptr::null()) == -1
                        || libc::setresgid(65_534, 65_534, 65_534) == -1
                        || libc::setresuid(65_534, 65_534, 65_534) == -1)
                {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    fn spawn_non_root_no_new_privileges_child() -> Child {
        let mut command = Command::new("/bin/sleep");
        command.arg("30");
        configure_non_root_no_new_privileges(&mut command);
        command.spawn().unwrap()
    }

    fn spawn_safe_multithreaded_child() -> Child {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "oracle::tests::safe_multithreaded_target_fixture",
            ])
            .env("P11SCOPE_TEST_MULTITHREADED_TARGET", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_non_root_no_new_privileges(&mut command);
        command.spawn().unwrap()
    }

    fn wait_for_multiple_tasks(pid: u32) {
        for _ in 0..100 {
            if std::fs::read_dir(format!("/proc/{pid}/task"))
                .is_ok_and(|entries| entries.count() >= 2)
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("multithreaded target fixture did not become ready");
    }

    #[test]
    fn valid_static_root_pid_facts_select_hardened_mode() {
        let mode = select_from_facts(
            &Scope::Pid(42),
            false,
            Some(HardenedFacts {
                observer_loader: static_loader(),
                observer_owner: 0,
                observer_mode: 0o100755,
                observer_status: ROOT_STATUS,
                target_status: TARGET_STATUS,
                observer_uid_map: FULL_UID_MAP,
                observer_user_namespace: (4, 1),
                init_user_namespace: (4, 1),
            }),
        )
        .unwrap();

        assert_eq!(mode, OracleMode::Hardened);
    }

    #[test]
    fn trusted_acknowledgement_is_only_a_fallback() {
        let mode = select_from_facts(
            &Scope::Pid(42),
            true,
            Some(HardenedFacts {
                observer_loader: static_loader(),
                observer_owner: 0,
                observer_mode: 0o100755,
                observer_status: ROOT_STATUS,
                target_status: TARGET_STATUS,
                observer_uid_map: FULL_UID_MAP,
                observer_user_namespace: (4, 1),
                init_user_namespace: (4, 1),
            }),
        )
        .unwrap();
        assert_eq!(mode, OracleMode::Hardened);
        assert_eq!(
            select_from_facts(&Scope::Pid(42), true, None).unwrap(),
            OracleMode::TrustedWorkload
        );
    }

    #[test]
    fn cgroup_requires_explicit_trusted_acknowledgement() {
        let scope = Scope::Cgroup {
            id: 7,
            path: PathBuf::from("/sys/fs/cgroup/test"),
        };
        let error = select_from_facts(&scope, false, None).unwrap_err();

        assert!(
            error.to_string().contains("--trusted-workload"),
            "{error:#}"
        );
        assert_eq!(
            select_from_facts(&scope, true, None).unwrap(),
            OracleMode::TrustedWorkload
        );
    }

    #[test]
    fn dynamic_or_non_root_observer_facts_are_refused() {
        for (loader, owner, mode, status) in [
            (
                ElfLoader {
                    interpreter: Some(PathBuf::from("/lib64/ld-linux-x86-64.so.2")),
                    needed: vec![OsString::from("libc.so.6")],
                    soname: None,
                },
                0,
                0o100755,
                ROOT_STATUS,
            ),
            (static_loader(), 1000, 0o100755, ROOT_STATUS),
            (static_loader(), 0, 0o100775, ROOT_STATUS),
            (static_loader(), 0, 0o100755, TARGET_STATUS),
        ] {
            let error = select_from_facts(
                &Scope::Pid(42),
                false,
                Some(HardenedFacts {
                    observer_loader: loader,
                    observer_owner: owner,
                    observer_mode: mode,
                    observer_status: status,
                    target_status: TARGET_STATUS,
                    observer_uid_map: FULL_UID_MAP,
                    observer_user_namespace: (4, 1),
                    init_user_namespace: (4, 1),
                }),
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("--trusted-workload"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn target_root_or_any_capability_is_refused() {
        for status in [
            ROOT_STATUS.to_string(),
            TARGET_STATUS.replace("1000\t1000\t1000\t1000", "0\t1000\t1000\t1000"),
            TARGET_STATUS.replace("1000\t1000\t1000\t1000", "1000\t0\t1000\t1000"),
            TARGET_STATUS.replace("1000\t1000\t1000\t1000", "1000\t1000\t0\t1000"),
            TARGET_STATUS.replace("1000\t1000\t1000\t1000", "1000\t1000\t1000\t0"),
            TARGET_STATUS.replace("CapInh:\t0000000000000000", "CapInh:\t0000000000080000"),
            TARGET_STATUS.replace("CapPrm:\t0000000000000000", "CapPrm:\t0000000000000080"),
            TARGET_STATUS.replace("CapEff:\t0000000000000000", "CapEff:\t0000000000080000"),
            TARGET_STATUS.replace("CapAmb:\t0000000000000000", "CapAmb:\t0000000000000020"),
            TARGET_STATUS.replace("CapInh:\t0000000000000000", "CapInh:\t0000000000000001"),
            TARGET_STATUS.replace("CapPrm:\t0000000000000000", "CapPrm:\t0000000000000001"),
            TARGET_STATUS.replace("CapEff:\t0000000000000000", "CapEff:\t0000000000000001"),
            TARGET_STATUS.replace("CapAmb:\t0000000000000000", "CapAmb:\t0000000000000001"),
        ] {
            let error = select_from_facts(
                &Scope::Pid(42),
                false,
                Some(HardenedFacts {
                    observer_loader: static_loader(),
                    observer_owner: 0,
                    observer_mode: 0o100755,
                    observer_status: ROOT_STATUS,
                    target_status: &status,
                    observer_uid_map: FULL_UID_MAP,
                    observer_user_namespace: (4, 1),
                    init_user_namespace: (4, 1),
                }),
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("--trusted-workload"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn target_requires_exact_no_new_privileges() {
        for status in [
            TARGET_STATUS.replace("NoNewPrivs:\t1\n", "NoNewPrivs:\t0\n"),
            TARGET_STATUS.replace("NoNewPrivs:\t1\n", ""),
            TARGET_STATUS.replace("NoNewPrivs:\t1\n", "NoNewPrivs:\t1\nNoNewPrivs:\t1\n"),
            TARGET_STATUS.replace("NoNewPrivs:\t1\n", "NoNewPrivs:\tnot-a-bit\n"),
        ] {
            let error = select_from_facts(
                &Scope::Pid(42),
                false,
                Some(HardenedFacts {
                    observer_loader: static_loader(),
                    observer_owner: 0,
                    observer_mode: 0o100755,
                    observer_status: ROOT_STATUS,
                    target_status: &status,
                    observer_uid_map: FULL_UID_MAP,
                    observer_user_namespace: (4, 1),
                    init_user_namespace: (4, 1),
                }),
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("--trusted-workload"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn divergent_unsafe_nonleader_task_status_is_refused() {
        validate_task_status(42, TARGET_STATUS).unwrap();
        let unsafe_nonleader =
            TARGET_STATUS.replace("CapEff:\t0000000000000000", "CapEff:\t0000000000000001");

        let error = validate_task_status(43, &unsafe_nonleader).unwrap_err();

        assert!(error.to_string().contains("task 43"), "{error:#}");
    }

    #[test]
    fn target_task_identity_set_must_stabilize() {
        let identity = TaskIdentity {
            directory: ProcFileIdentity {
                device: 7,
                inode: 11,
            },
            status: ProcFileIdentity {
                device: 7,
                inode: 12,
            },
            start_time: 13,
        };
        let first = BTreeMap::from([(42, identity)]);
        ensure_same_task_set(42, &first, &first).unwrap();

        for second in [
            BTreeMap::new(),
            BTreeMap::from([(43, identity)]),
            BTreeMap::from([(
                42,
                TaskIdentity {
                    start_time: 23,
                    ..identity
                },
            )]),
        ] {
            let error = ensure_same_task_set(42, &first, &second).unwrap_err();
            assert!(error.to_string().contains("task set changed"), "{error:#}");
        }
    }

    #[test]
    fn pinned_target_revalidation_detects_process_exit() {
        let mut child = spawn_non_root_no_new_privileges_child();
        let oracle = OracleSelection::hardened(PinnedTarget::pin(child.id()).unwrap());
        oracle.revalidate().unwrap();

        child.kill().unwrap();
        child.wait().unwrap();
        let error = oracle.revalidate().unwrap_err();

        assert!(error.to_string().contains("exited"), "{error:#}");
    }

    #[test]
    fn pinned_target_revalidation_accepts_safe_multithreaded_process() {
        let mut child = spawn_safe_multithreaded_child();
        wait_for_multiple_tasks(child.id());

        let result = PinnedTarget::pin(child.id()).and_then(|target| target.revalidate());
        child.kill().unwrap();
        child.wait().unwrap();

        result.unwrap();
    }

    #[test]
    fn safe_multithreaded_target_fixture() {
        if std::env::var_os("P11SCOPE_TEST_MULTITHREADED_TARGET").is_none() {
            return;
        }
        let other = std::thread::spawn(|| std::thread::sleep(Duration::from_secs(30)));
        std::thread::sleep(Duration::from_secs(30));
        other.join().unwrap();
    }

    #[test]
    fn target_identity_revalidation_detects_pid_reuse_facts() {
        let pinned = TargetIdentity {
            directory: ProcFileIdentity {
                device: 7,
                inode: 11,
            },
            status: ProcFileIdentity {
                device: 7,
                inode: 12,
            },
            tasks: ProcFileIdentity {
                device: 7,
                inode: 13,
            },
            start_time: 14,
        };
        for current in [
            TargetIdentity {
                directory: ProcFileIdentity {
                    device: 7,
                    inode: 21,
                },
                ..pinned
            },
            TargetIdentity {
                status: ProcFileIdentity {
                    device: 7,
                    inode: 22,
                },
                ..pinned
            },
            TargetIdentity {
                start_time: 23,
                ..pinned
            },
        ] {
            let error = ensure_same_target(42, pinned, current).unwrap_err();
            assert!(error.to_string().contains("PID reuse"), "{error:#}");
        }
    }

    #[test]
    fn proc_start_time_parser_handles_spaces_and_closing_parenthesis_in_comm() {
        let stat = b"42 (odd ) name) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242 20\n";

        assert_eq!(parse_proc_start_time(stat).unwrap(), 4242);
    }

    #[test]
    fn procfs_binding_requires_one_canonical_matching_nspid() {
        let identity = ProcFileIdentity {
            device: 7,
            inode: 11,
        };
        validate_procfs_binding_facts(42, identity, identity, "NSpid:\t42\n").unwrap();

        for status in [
            "Uid:\t1000\t1000\t1000\t1000\n",
            "NSpid:\tnot-a-pid\n",
            "NSpid:\t042\n",
            "NSpid:\t42\t1\n",
            "NSpid:\t42\nNSpid:\t42\n",
            "NSpid:\t43\n",
        ] {
            let error = validate_procfs_binding_facts(42, identity, identity, status).unwrap_err();
            assert!(error.to_string().contains("NSpid"), "{error:#}");
        }
    }

    #[test]
    fn procfs_binding_requires_self_and_numeric_identity_to_match() {
        let self_identity = ProcFileIdentity {
            device: 7,
            inode: 11,
        };
        let numeric_identity = ProcFileIdentity {
            device: 7,
            inode: 12,
        };

        let error =
            validate_procfs_binding_facts(42, self_identity, numeric_identity, "NSpid:\t42\n")
                .unwrap_err();

        assert!(error.to_string().contains("identity"), "{error:#}");
    }

    #[test]
    fn partial_or_different_user_namespace_is_refused() {
        for (uid_map, observer_namespace, init_namespace) in [
            ("0 0 65536\n", (4, 1), (4, 1)),
            ("0 0 4294967295\n1 1 1\n", (4, 1), (4, 1)),
            (FULL_UID_MAP, (4, 1), (4, 2)),
            (FULL_UID_MAP, (0, 0), (0, 0)),
        ] {
            let error = select_from_facts(
                &Scope::Pid(42),
                false,
                Some(HardenedFacts {
                    observer_loader: static_loader(),
                    observer_owner: 0,
                    observer_mode: 0o100755,
                    observer_status: ROOT_STATUS,
                    target_status: TARGET_STATUS,
                    observer_uid_map: uid_map,
                    observer_user_namespace: observer_namespace,
                    init_user_namespace: init_namespace,
                }),
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("--trusted-workload"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn malformed_or_incomplete_proc_status_is_refused() {
        for status in [
            "",
            "Uid:\t1000\t1000\t1000\n",
            "Uid:\t1000\t1000\t1000\t1000\nCapInh:\tnot-hex\nCapPrm:\t0\nCapEff:\t0\nCapAmb:\t0\n",
            "Uid:\t1000\t1000\t1000\t1000\nUid:\t1000\t1000\t1000\t1000\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapAmb:\t0\n",
        ] {
            let error = parse_status(status).unwrap_err();
            assert!(error.to_string().contains("process status"), "{error:#}");
        }
    }

    #[test]
    fn glibc_official_graph_is_resolved_once() {
        let helper = ElfLoader {
            interpreter: Some(PathBuf::from("/lib64/ld-linux-x86-64.so.2")),
            needed: ["libgcc_s.so.1", "libc.so.6", "ld-linux-x86-64.so.2"]
                .into_iter()
                .map(OsString::from)
                .collect(),
            soname: None,
        };
        let mut resolved = Vec::new();

        let graph = prepare_glibc_graph(&helper, |name: &std::ffi::OsStr| -> Result<ElfLoader> {
            let name = name.to_string_lossy().into_owned();
            resolved.push(name.clone());
            let needed = match name.as_str() {
                "ld-linux-x86-64.so.2" => vec![],
                "libc.so.6" => vec![OsString::from("ld-linux-x86-64.so.2")],
                "libgcc_s.so.1" => vec![
                    OsString::from("libc.so.6"),
                    OsString::from("ld-linux-x86-64.so.2"),
                ],
                _ => return Err(anyhow!("unexpected runtime object {name}")),
            };
            Ok(ElfLoader {
                interpreter: None,
                needed,
                soname: Some(OsString::from(name)),
            })
        })
        .unwrap();

        assert_eq!(
            graph.keys().cloned().collect::<Vec<_>>(),
            ["ld-linux-x86-64.so.2", "libc.so.6", "libgcc_s.so.1"]
        );
        resolved.sort();
        assert_eq!(
            resolved,
            ["ld-linux-x86-64.so.2", "libc.so.6", "libgcc_s.so.1"]
        );
    }

    #[test]
    fn glibc_runtime_names_are_exact_safe_basenames() {
        for invalid in [
            OsString::from(""),
            OsString::from("$ORIGIN"),
            OsString::from("bad/name"),
            OsString::from("."),
            OsString::from(".."),
            OsString::from("libm.so.6"),
            OsString::from_vec(b"bad\0name".to_vec()),
        ] {
            let helper = ElfLoader {
                interpreter: Some(PathBuf::from("/lib64/ld-linux-x86-64.so.2")),
                needed: vec![invalid.clone()],
                soname: None,
            };
            let error =
                prepare_glibc_graph(&helper, |name: &std::ffi::OsStr| -> Result<ElfLoader> {
                    Ok(ElfLoader {
                        interpreter: None,
                        needed: vec![],
                        soname: Some(name.to_os_string()),
                    })
                })
                .unwrap_err();
            assert!(error.to_string().contains("runtime name"), "{error:#}");
        }
    }

    #[test]
    fn glibc_helper_loader_and_soname_facts_are_exact() {
        let resolve = |name: &std::ffi::OsStr| -> Result<ElfLoader> {
            Ok(ElfLoader {
                interpreter: None,
                needed: vec![],
                soname: Some(name.to_os_string()),
            })
        };
        for helper in [
            ElfLoader {
                interpreter: None,
                needed: vec![],
                soname: None,
            },
            ElfLoader {
                interpreter: Some(PathBuf::from("/lib/ld-linux-x86-64.so.2")),
                needed: vec![],
                soname: None,
            },
            ElfLoader {
                interpreter: Some(PathBuf::from("/lib64/ld-linux-x86-64.so.2")),
                needed: vec![],
                soname: Some(OsString::from("helper")),
            },
        ] {
            assert!(prepare_glibc_graph(&helper, resolve).is_err());
        }

        let helper = ElfLoader {
            interpreter: Some(PathBuf::from("/lib64/ld-linux-x86-64.so.2")),
            needed: vec![],
            soname: None,
        };
        for loader in [
            ElfLoader {
                interpreter: Some(PathBuf::from("/lib64/ld-linux-x86-64.so.2")),
                needed: vec![],
                soname: Some(OsString::from("ld-linux-x86-64.so.2")),
            },
            ElfLoader {
                interpreter: None,
                needed: vec![OsString::from("libc.so.6")],
                soname: Some(OsString::from("ld-linux-x86-64.so.2")),
            },
            ElfLoader {
                interpreter: None,
                needed: vec![],
                soname: Some(OsString::from("libc.so.6")),
            },
        ] {
            let result = prepare_glibc_graph(&helper, |name| {
                if name == "ld-linux-x86-64.so.2" {
                    Ok(loader.clone())
                } else {
                    resolve(name)
                }
            });
            assert!(result.is_err());
        }
    }

    #[test]
    fn glibc_nonloader_runtime_may_name_the_exact_interpreter() {
        let helper = ElfLoader {
            interpreter: Some(PathBuf::from(GLIBC_INTERP)),
            needed: vec![OsString::from("libc.so.6")],
            soname: None,
        };

        let graph = prepare_glibc_graph(&helper, |name| {
            Ok(if name == OsStr::new(GLIBC_LOADER) {
                ElfLoader {
                    interpreter: None,
                    needed: vec![],
                    soname: Some(OsString::from(GLIBC_LOADER)),
                }
            } else {
                ElfLoader {
                    interpreter: Some(PathBuf::from(GLIBC_INTERP)),
                    needed: vec![OsString::from(GLIBC_LOADER)],
                    soname: Some(name.to_os_string()),
                }
            })
        })
        .unwrap();

        assert_eq!(graph.len(), 2);
    }

    #[test]
    fn glibc_distinct_runtime_candidates_are_ambiguous() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("first.so");
        let second = dir.path().join("second.so");
        let alias = dir.path().join("alias.so");
        std::fs::copy("/bin/true", &first).unwrap();
        std::fs::copy(&first, &second).unwrap();
        std::fs::hard_link(&first, &alias).unwrap();

        let error = unique_runtime_candidate(vec![
            std::fs::File::open(&first).unwrap(),
            std::fs::File::open(&second).unwrap(),
        ])
        .unwrap_err();
        assert!(error.to_string().contains("ambiguous"), "{error:#}");
        let selected = unique_runtime_candidate(vec![
            std::fs::File::open(&first).unwrap(),
            std::fs::File::open(&alias).unwrap(),
        ])
        .unwrap();
        assert_eq!(
            selected.metadata().unwrap().ino(),
            first.metadata().unwrap().ino()
        );
    }

    #[test]
    fn glibc_loader_candidate_must_be_the_pinned_interpreter() {
        let dir = tempfile::tempdir().unwrap();
        let interpreter = dir.path().join("interpreter");
        let alias = dir.path().join("alias");
        let replacement = dir.path().join("replacement");
        std::fs::copy("/bin/true", &interpreter).unwrap();
        std::fs::hard_link(&interpreter, &alias).unwrap();
        std::fs::copy(&interpreter, &replacement).unwrap();

        let error =
            pinned_loader_candidate(&std::fs::File::open(&interpreter).unwrap(), Vec::new())
                .unwrap_err();
        assert!(error.to_string().contains("unresolved"), "{error:#}");
        pinned_loader_candidate(
            &std::fs::File::open(&interpreter).unwrap(),
            vec![std::fs::File::open(&alias).unwrap()],
        )
        .unwrap();
        let error = pinned_loader_candidate(
            &std::fs::File::open(&interpreter).unwrap(),
            vec![std::fs::File::open(&replacement).unwrap()],
        )
        .unwrap_err();
        assert!(error.to_string().contains("interpreter"), "{error:#}");
    }

    #[test]
    fn glibc_search_directories_are_dirfd_walked_and_protected() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir_all(root.path().join("usr/lib/x86_64-linux-gnu")).unwrap();
        for directory in ["usr", "usr/lib", "usr/lib/x86_64-linux-gnu"] {
            std::fs::set_permissions(
                root.path().join(directory),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        let owner = unsafe { libc::geteuid() };
        let authority = AuthorityRoot::open(root.path(), owner).unwrap();

        let directory = authority
            .open_directory(Path::new("/usr/lib/x86_64-linux-gnu"), true)
            .unwrap()
            .unwrap();
        assert!(directory.as_raw_fd() > 2);
        assert!(
            authority
                .open_directory(Path::new("/usr/lib64"), true)
                .unwrap()
                .is_none()
        );

        std::fs::set_permissions(
            root.path().join("usr/lib"),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        let error = authority
            .open_directory(Path::new("/usr/lib/x86_64-linux-gnu"), true)
            .unwrap_err();
        assert!(error.to_string().contains("protected"), "{error:#}");
    }

    #[test]
    fn glibc_preload_is_exactly_absent_or_leased_empty() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir(root.path().join("etc")).unwrap();
        std::fs::set_permissions(
            root.path().join("etc"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let authority = AuthorityRoot::open(root.path(), unsafe { libc::geteuid() }).unwrap();
        let preload = root.path().join("etc/ld.so.preload");

        let state =
            PreloadState::capture(&authority, |_| panic!("absent preload was retained")).unwrap();
        assert!(state.is_absent());
        state.revalidate().unwrap();

        std::fs::write(&preload, []).unwrap();
        std::fs::set_permissions(&preload, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = state.revalidate().unwrap_err();
        assert!(error.to_string().contains("appeared"), "{error:#}");
        std::fs::remove_file(&preload).unwrap();

        std::fs::write(&preload, []).unwrap();
        std::fs::set_permissions(&preload, std::fs::Permissions::from_mode(0o644)).unwrap();
        let mut retained = 0;
        let state = PreloadState::capture(&authority, |_| {
            retained += 1;
            Ok(())
        })
        .unwrap();
        assert!(!state.is_absent());
        assert_eq!(retained, 1);
        state.revalidate().unwrap();

        std::fs::write(&preload, b"injected.so\n").unwrap();
        retained = 0;
        assert!(
            PreloadState::capture(&authority, |_| {
                retained += 1;
                Ok(())
            })
            .is_err()
        );
        assert_eq!(retained, 1, "content was checked before retention");

        std::fs::write(&preload, []).unwrap();
        let replacement = root.path().join("etc/replacement");
        let error = PreloadState::capture(&authority, |_| {
            std::fs::rename(&preload, root.path().join("etc/original"))?;
            std::fs::write(&replacement, [])?;
            std::fs::rename(&replacement, &preload)?;
            Ok(())
        })
        .unwrap_err();
        assert!(error.to_string().contains("changed"), "{error:#}");
    }

    #[test]
    fn glibc_interpreter_path_walks_bounded_protected_symlinks() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir_all(root.path().join("usr/lib/x86_64-linux-gnu")).unwrap();
        for directory in ["usr", "usr/lib", "usr/lib/x86_64-linux-gnu"] {
            std::fs::set_permissions(
                root.path().join(directory),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        let loader = root
            .path()
            .join("usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2");
        std::fs::copy("/bin/true", &loader).unwrap();
        std::fs::set_permissions(&loader, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("usr/lib/x86_64-linux-gnu", root.path().join("lib64")).unwrap();
        let authority = AuthorityRoot::open(root.path(), unsafe { libc::geteuid() }).unwrap();

        let interpreter = authority
            .open_regular(Path::new(GLIBC_INTERP), false)
            .unwrap()
            .unwrap();
        assert_eq!(
            mapping_file_key(&interpreter).unwrap(),
            mapping_file_key(&std::fs::File::open(&loader).unwrap()).unwrap()
        );

        for index in 0..9 {
            let target = if index == 8 {
                OsString::from("usr/lib/x86_64-linux-gnu")
            } else {
                OsString::from(format!("link{}", index + 1))
            };
            std::os::unix::fs::symlink(target, root.path().join(format!("link{index}"))).unwrap();
        }
        let error = authority
            .open_regular(Path::new("/link0/ld-linux-x86-64.so.2"), false)
            .unwrap_err();
        assert!(error.to_string().contains("symlink"), "{error:#}");
    }

    #[test]
    fn glibc_runtime_candidates_use_strict_same_directory_symlinks() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        for directory in ["usr", "usr/lib", "usr/lib/x86_64-linux-gnu", "usr/lib64"] {
            std::fs::create_dir(root.path().join(directory)).unwrap();
            std::fs::set_permissions(
                root.path().join(directory),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        let first = root.path().join("usr/lib/x86_64-linux-gnu");
        let second = root.path().join("usr/lib64");
        std::fs::copy("/bin/true", first.join("libc.so.6")).unwrap();
        std::fs::set_permissions(
            first.join("libc.so.6"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::fs::hard_link(first.join("libc.so.6"), second.join("libc-real.so.6")).unwrap();
        std::os::unix::fs::symlink("libc-real.so.6", second.join("libc.so.6")).unwrap();
        let authority = AuthorityRoot::open(root.path(), unsafe { libc::geteuid() }).unwrap();
        let directories = [
            authority
                .open_directory(Path::new("/usr/lib/x86_64-linux-gnu"), false)
                .unwrap()
                .unwrap(),
            authority
                .open_directory(Path::new("/usr/lib64"), false)
                .unwrap()
                .unwrap(),
        ];

        let candidates = runtime_candidates(&directories, OsStr::new("libc.so.6"), unsafe {
            libc::geteuid()
        })
        .unwrap();
        assert_eq!(candidates.len(), 2);
        unique_runtime_candidate(candidates).unwrap();

        std::fs::copy("/bin/true", first.join("libgcc_s.so.1")).unwrap();
        std::fs::set_permissions(
            first.join("libgcc_s.so.1"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        std::os::unix::fs::symlink(
            "../lib/x86_64-linux-gnu/libgcc_s.so.1",
            second.join("libgcc_s.so.1"),
        )
        .unwrap();
        let error = runtime_candidates(&directories, OsStr::new("libgcc_s.so.1"), unsafe {
            libc::geteuid()
        })
        .unwrap_err();
        assert!(error.to_string().contains("symlink target"), "{error:#}");
    }

    #[test]
    fn glibc_private_alias_directory_revalidates_and_cleans_exactly() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir_all(root.path().join("run/p11scope")).unwrap();
        for directory in ["run", "run/p11scope"] {
            std::fs::set_permissions(
                root.path().join(directory),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        let owner = unsafe { libc::geteuid() };
        let authority = AuthorityRoot::open(root.path(), owner).unwrap();
        let parent = authority
            .open_directory(Path::new("/run/p11scope"), false)
            .unwrap()
            .unwrap();
        let target = normalize_file_fd(std::fs::File::open("/bin/true").unwrap()).unwrap();
        let replacement = normalize_file_fd(std::fs::File::open("/bin/false").unwrap()).unwrap();
        assert!(target.as_raw_fd() > 2);
        assert!(replacement.as_raw_fd() > 2);
        let mut private =
            PrivateAliasDir::create(&parent, owner, vec![(OsString::from("libc.so.6"), &target)])
                .unwrap();
        let random_name = private
            .name()
            .to_str()
            .unwrap()
            .strip_prefix("oracle-")
            .unwrap();
        assert_eq!(random_name.len(), 32);
        assert!(random_name.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let child = root.path().join("run/p11scope").join(private.name());
        let alias = child.join("libc.so.6");
        assert_eq!(
            std::fs::read_link(&alias).unwrap(),
            PathBuf::from(format!("/proc/self/fd/{}", target.as_raw_fd()))
        );
        private.revalidate().unwrap();

        unsafe { libc::fchmod(private.directory_fd(), 0o700) };
        std::os::unix::fs::symlink("/proc/self/fd/0", child.join("extra")).unwrap();
        unsafe { libc::fchmod(private.directory_fd(), 0o511) };
        assert!(
            private
                .revalidate()
                .unwrap_err()
                .to_string()
                .contains("entry set")
        );
        assert!(private.cleanup().is_err());
        unsafe { libc::fchmod(private.directory_fd(), 0o700) };
        std::fs::remove_file(child.join("extra")).unwrap();
        std::fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(format!("/proc/self/fd/{}", replacement.as_raw_fd()), &alias)
            .unwrap();
        unsafe { libc::fchmod(private.directory_fd(), 0o511) };
        assert!(
            private
                .revalidate()
                .unwrap_err()
                .to_string()
                .contains("alias")
        );
        assert!(private.cleanup().is_err());
        unsafe { libc::fchmod(private.directory_fd(), 0o700) };
        std::fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(format!("/proc/self/fd/{}", target.as_raw_fd()), &alias)
            .unwrap();
        unsafe { libc::fchmod(private.directory_fd(), 0o511) };
        private.cleanup().unwrap();
        assert!(!child.exists());

        let dropped_name = {
            let private = PrivateAliasDir::create(
                &parent,
                owner,
                vec![(OsString::from("libc.so.6"), &target)],
            )
            .unwrap();
            private.name().to_os_string()
        };
        assert!(!root.path().join("run/p11scope").join(dropped_name).exists());
    }

    #[test]
    fn glibc_private_alias_cleanup_retries_after_partial_unlink() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir_all(root.path().join("run/p11scope")).unwrap();
        for directory in ["run", "run/p11scope"] {
            std::fs::set_permissions(
                root.path().join(directory),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        let owner = unsafe { libc::geteuid() };
        let authority = AuthorityRoot::open(root.path(), owner).unwrap();
        let parent = authority
            .open_directory(Path::new("/run/p11scope"), false)
            .unwrap()
            .unwrap();
        let target = normalize_file_fd(std::fs::File::open("/bin/true").unwrap()).unwrap();
        let mut private = PrivateAliasDir::create(
            &parent,
            owner,
            vec![
                (OsString::from("libc.so.6"), &target),
                (OsString::from("libgcc_s.so.1"), &target),
            ],
        )
        .unwrap();
        private.revalidate().unwrap();
        assert_eq!(unsafe { libc::fchmod(private.directory_fd(), 0o700) }, 0);
        private.ready = false;
        let mut unlinks = 0;
        let error = private
            .unlink_aliases(|directory, name| {
                unlinks += 1;
                if unlinks == 2 {
                    return Err(std::io::Error::from_raw_os_error(libc::EIO));
                }
                if unsafe { libc::unlinkat(directory, name.as_ptr(), 0) } == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            })
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert_eq!(private.aliases.len(), 1);
        private.cleanup().unwrap();

        assert_eq!(
            std::fs::read_dir(root.path().join("run/p11scope"))
                .unwrap()
                .count(),
            0
        );
        let failed =
            PrivateAliasDir::create(&parent, owner, vec![(OsString::from("$ORIGIN"), &target)]);
        assert!(failed.is_err());
        assert_eq!(
            std::fs::read_dir(root.path().join("run/p11scope"))
                .unwrap()
                .count(),
            0,
            "initialization failure leaked the exact empty child"
        );

        let mut partial = PrivateAliasDir::create(&parent, owner, Vec::new()).unwrap();
        let partial_name = partial.name().to_os_string();
        assert_eq!(unsafe { libc::fchmod(partial.directory_fd(), 0o700) }, 0);
        partial.ready = false;
        partial.directory = None;
        partial.cleanup().unwrap();
        assert!(
            std::fs::symlink_metadata(root.path().join("run/p11scope").join(partial_name))
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        );
    }
}
