//! `p11scope discover` — locate and exec the unprivileged helper.
//! p11scope never dlopens a provider itself: it is privileged, static,
//! and must not run vendor constructors in its own address space.

use crate::attach::Scope;
use anyhow::{Context as _, Result, anyhow, bail};
use p11scope_manifest::identity::{MappingFileKey, inspect_file, mapping_file_key, open_object};
use p11scope_manifest::manifest::{Manifest, ProvenanceObject, SCHEMA};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::{File, Metadata, OpenOptions};
use std::io::Read;
use std::os::fd::{AsRawFd as _, BorrowedFd, FromRawFd as _, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub use crate::oracle::OracleSelection;

const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_STABILIZATION_PASSES: usize = 8;
const MAX_PROVENANCE_OBJECTS: usize = p11scope_ebpf_common::MAX_SLOTS as usize;

fn target_id(name: &str) -> Option<u32> {
    std::env::var(name)
        .ok()?
        .parse()
        .ok()
        .filter(|value| *value != 0)
}

#[repr(C)]
struct CapHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

fn clear_capabilities() -> std::io::Result<()> {
    let mut header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    if unsafe { libc::syscall(libc::SYS_capset, &mut header, data.as_ptr()) } != 0
        || unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn has_effective_privilege() -> Result<bool> {
    if unsafe { libc::geteuid() } == 0 {
        return Ok(true);
    }
    let mut header = CapHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    if unsafe { libc::syscall(libc::SYS_capget, &mut header, data.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("reading effective capabilities");
    }
    Ok(data.iter().any(|word| word.effective != 0))
}

fn validate_helper_metadata(metadata: &Metadata, expected_owner: u32) -> Result<()> {
    if !metadata.file_type().is_file() {
        bail!("discovery oracle helper is not a regular file");
    }
    if metadata.uid() != expected_owner {
        bail!(
            "discovery oracle helper owner is uid {}, expected uid {expected_owner}",
            metadata.uid()
        );
    }
    if metadata.mode() & 0o111 == 0 {
        bail!("discovery oracle helper is not executable");
    }
    if metadata.mode() & 0o022 != 0 {
        bail!("discovery oracle helper is group/world writable");
    }
    Ok(())
}

fn open_trusted_helper(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("opening discovery oracle helper {}", path.display()))?;
    let metadata = file
        .metadata()
        .context("reading discovery oracle helper metadata")?;
    let euid = unsafe { libc::geteuid() };
    let expected_owner = if has_effective_privilege()? || metadata.uid() == 0 {
        0
    } else {
        euid
    };
    validate_helper_metadata(&metadata, expected_owner)?;
    Ok(file)
}

fn append_bounded(output: &mut Vec<u8>, bytes: &[u8], limit: u64) -> Result<()> {
    if (output.len() as u64)
        .checked_add(bytes.len() as u64)
        .is_none_or(|length| length > limit)
    {
        bail!("discovery oracle output exceeds the {limit}-byte limit");
    }
    output.extend_from_slice(bytes);
    Ok(())
}

/// A final oracle pass plus the exact closure leases that made that pass
/// eligible to authorize attachment. The guard must outlive comparison.
#[derive(Debug)]
pub struct StableDiscovery {
    manifest: Manifest,
    leases: ClosureLeases,
    module: PathBuf,
}

impl StableDiscovery {
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn ensure_stable(&self) -> Result<()> {
        self.leases.ensure().map_err(anyhow::Error::msg)?;
        self.leases.revalidate_seed(&self.module)
    }
}

#[derive(Debug)]
struct RetainedProvenanceObject {
    identity: p11scope_manifest::identity::ObjectIdentity,
    file: File,
}

#[derive(Debug)]
pub(crate) struct ClosureLeases {
    // Drop lease-bearing fds before restoring SIGIO delivery.
    objects: BTreeMap<MappingFileKey, RetainedProvenanceObject>,
    influences: Vec<File>,
    monitor: crate::verify::SynchronousLeaseMonitor,
    seed: MappingFileKey,
    total_bytes: u64,
}

impl ClosureLeases {
    fn new(module: &Path) -> Result<Self> {
        let monitor = crate::verify::SynchronousLeaseMonitor::new().map_err(anyhow::Error::msg)?;
        let (record, file) = current_provenance_object(module)?;
        let seed = record_key(&record);
        let mut leases = Self {
            objects: BTreeMap::new(),
            influences: Vec::new(),
            monitor,
            seed,
            total_bytes: 0,
        };
        leases.retain(record, file)?;
        Ok(leases)
    }

    fn retain_reported(&mut self, record: &ProvenanceObject) -> Result<()> {
        let key = record_key(record);
        if let Some(retained) = self.objects.get(&key) {
            if !same_identity(&retained.identity, &record.identity) {
                bail!("provenance mapping {key:?} changed whole-file identity between passes");
            }
            return Ok(());
        }
        let (current, file) = current_provenance_object(Path::new(&record.path))?;
        if record_key(&current) != key {
            bail!(
                "provenance mapping {} changed device/inode before it could be leased",
                record.path
            );
        }
        if !same_identity(&current.identity, &record.identity) {
            bail!(
                "provenance mapping {} changed whole-file identity before it could be leased",
                record.path
            );
        }
        self.retain(current, file)
    }

    fn retain(&mut self, record: ProvenanceObject, file: File) -> Result<()> {
        if self.objects.len() >= MAX_PROVENANCE_OBJECTS {
            bail!("provenance closure exceeds the {MAX_PROVENANCE_OBJECTS}-object limit");
        }
        let len = file
            .metadata()
            .with_context(|| format!("reading provenance object metadata for {}", record.path))?
            .len();
        let total = self
            .total_bytes
            .checked_add(len)
            .ok_or_else(|| anyhow!("provenance closure size overflowed u64"))?;
        if total > crate::verify::MAX_TOTAL_OBJECT_BYTES {
            bail!(
                "provenance closure totals more than the {}-byte limit",
                crate::verify::MAX_TOTAL_OBJECT_BYTES
            );
        }
        self.monitor.acquire(&file).map_err(anyhow::Error::msg)?;
        self.total_bytes = total;
        self.objects.insert(
            record_key(&record),
            RetainedProvenanceObject {
                identity: record.identity,
                file,
            },
        );
        self.ensure().map_err(anyhow::Error::msg)
    }

    fn keys(&self) -> BTreeSet<MappingFileKey> {
        self.objects.keys().copied().collect()
    }

    pub(crate) fn retain_influence(&mut self, file: File, label: &str) -> Result<RawFd> {
        let file = normalize_influence_fd(file)?;
        let len = file
            .metadata()
            .with_context(|| format!("reading hardened influence metadata for {label}"))?
            .len();
        let total = self
            .total_bytes
            .checked_add(len)
            .ok_or_else(|| anyhow!("hardened influence closure size overflowed u64"))?;
        if total > crate::verify::MAX_TOTAL_OBJECT_BYTES {
            bail!(
                "hardened influence closure totals more than the {}-byte limit",
                crate::verify::MAX_TOTAL_OBJECT_BYTES
            );
        }
        self.monitor.acquire(&file).map_err(anyhow::Error::msg)?;
        let fd = file.as_raw_fd();
        self.total_bytes = total;
        self.influences.push(file);
        self.ensure().map_err(anyhow::Error::msg)?;
        Ok(fd)
    }

    pub(crate) fn file(&self, fd: RawFd) -> Option<&File> {
        self.influences
            .iter()
            .find(|influence| influence.as_raw_fd() == fd)
    }

    fn revalidate_seed(&self, module: &Path) -> Result<()> {
        let (record, _file) = current_provenance_object(module)?;
        let Some(retained) = self.objects.get(&self.seed) else {
            bail!("internal error: provenance seed lease is missing");
        };
        if record_key(&record) != self.seed || !same_identity(&record.identity, &retained.identity)
        {
            bail!("provenance module {} was replaced", module.display());
        }
        Ok(())
    }

    pub(crate) fn ensure(&self) -> Result<(), String> {
        self.monitor.ensure(self.files())
    }

    pub(crate) fn take_break(&self) -> Result<bool, String> {
        self.monitor.take_break(self.files())
    }

    #[allow(dead_code, reason = "polled by the hardened child supervisor in C3.3")]
    pub(crate) fn event_fd(&self) -> BorrowedFd<'_> {
        self.monitor.event_fd()
    }

    fn files(&self) -> impl Iterator<Item = &File> {
        self.objects
            .values()
            .map(|object| &object.file)
            .chain(self.influences.iter())
    }
}

fn normalize_influence_fd(file: File) -> Result<File> {
    if file.as_raw_fd() > 2 {
        return Ok(file);
    }
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if fd == -1 {
        return Err(std::io::Error::last_os_error())
            .context("moving hardened influence fd above stdio");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn same_identity(
    left: &p11scope_manifest::identity::ObjectIdentity,
    right: &p11scope_manifest::identity::ObjectIdentity,
) -> bool {
    left.kind == right.kind
        && left.value == right.value
        && left.sha256 == right.sha256
        && left.reusable == right.reusable
}

fn record_key(record: &ProvenanceObject) -> MappingFileKey {
    MappingFileKey {
        device_major: record.device_major,
        device_minor: record.device_minor,
        inode: record.inode,
    }
}

fn current_provenance_object(path: &Path) -> Result<(ProvenanceObject, File)> {
    if !path.is_absolute() {
        bail!(
            "provenance object path must be absolute: {}",
            path.display()
        );
    }
    let file = open_object(path)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("opening provenance object {}", path.display()))?;
    let key = mapping_file_key(&file).map_err(anyhow::Error::msg)?;
    let identity = inspect_file(&file)
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("identifying provenance object {}", path.display()))?
        .identity;
    if !identity.reusable || identity.sha256.as_deref().is_none_or(|sha| sha.len() != 64) {
        bail!(
            "provenance object {} has no reusable whole-file SHA-256",
            path.display()
        );
    }
    Ok((
        ProvenanceObject {
            path: path.display().to_string(),
            device_major: key.device_major,
            device_minor: key.device_minor,
            inode: key.inode,
            identity,
        },
        file,
    ))
}

fn closure_keys(manifest: &Manifest) -> Result<BTreeSet<MappingFileKey>> {
    if manifest.provenance_objects.is_empty()
        || manifest.provenance_objects.len() > MAX_PROVENANCE_OBJECTS
    {
        bail!(
            "discovery pass reported {} provenance objects; expected 1..={MAX_PROVENANCE_OBJECTS}",
            manifest.provenance_objects.len()
        );
    }
    let mut keys = BTreeSet::new();
    for object in &manifest.provenance_objects {
        if !Path::new(&object.path).is_absolute() || object.inode == 0 {
            bail!("discovery pass reported an invalid provenance object");
        }
        if !object.identity.reusable
            || object
                .identity
                .sha256
                .as_deref()
                .is_none_or(|sha| sha.len() != 64)
        {
            bail!(
                "discovery pass provenance object {} has no reusable whole-file SHA-256",
                object.path
            );
        }
        if !keys.insert(record_key(object)) {
            bail!("discovery pass reported a duplicate provenance device/inode");
        }
    }
    Ok(keys)
}

fn stabilize(module: &Path, mut pass: impl FnMut() -> Result<Manifest>) -> Result<StableDiscovery> {
    let mut leases = ClosureLeases::new(module)?;
    let mut previous = None;
    for _ in 0..MAX_STABILIZATION_PASSES {
        leases.ensure().map_err(anyhow::Error::msg)?;
        leases.revalidate_seed(module)?;
        let preleased = leases.keys();
        let manifest = pass()?;
        leases.revalidate_seed(module)?;
        leases.ensure().map_err(anyhow::Error::msg)?;
        let current = closure_keys(&manifest)?;
        if !current.contains(&leases.seed) {
            bail!("discovery pass omitted the selected provenance module mapping");
        }
        let already_leased = current.is_subset(&preleased);
        for object in &manifest.provenance_objects {
            leases.retain_reported(object)?;
        }
        leases.ensure().map_err(anyhow::Error::msg)?;
        if already_leased && previous.as_ref() == Some(&current) {
            return Ok(StableDiscovery {
                manifest,
                leases,
                module: module.to_path_buf(),
            });
        }
        previous = Some(current);
    }
    bail!("provenance closure did not stabilize within {MAX_STABILIZATION_PASSES} discovery passes")
}

/// Runs the installed sibling helper until one complete pass used only a
/// pre-leased, unchanged exact executable-mapping closure.
pub fn select_oracle(scope: &Scope, trusted_workload: bool) -> Result<OracleSelection> {
    crate::oracle::select(scope, trusted_workload)
}

pub fn rediscover_stable(module: &Path, selection: &OracleSelection) -> Result<StableDiscovery> {
    if !module.is_absolute() {
        bail!("--provenance-module must be an absolute path");
    }
    let helper_path = std::env::current_exe()
        .context("locating the running p11scope executable")?
        .parent()
        .ok_or_else(|| anyhow!("running p11scope executable has no parent directory"))?
        .join("p11scope-discover");
    rediscover_stable_selected(&helper_path, module, selection)
}

fn rediscover_stable_selected(
    helper_path: &Path,
    module: &Path,
    selection: &OracleSelection,
) -> Result<StableDiscovery> {
    match selection.mode() {
        crate::oracle::OracleMode::TrustedWorkload => {
            rediscover_stable_with_helper(helper_path, module)
        }
        crate::oracle::OracleMode::Hardened => {
            let helper = open_trusted_helper(helper_path)?;
            let mut leases = ClosureLeases::new(module)?;
            let mut prepared = crate::oracle::prepare_glibc(helper, helper_path, &mut leases)?;
            let validation = prepared.revalidate();
            let cleanup = prepared.cleanup();
            drop(prepared);
            if let Err(error) = cleanup {
                return Err(error).context("cleaning hardened glibc preparation");
            }
            let lease_check = leases.ensure().map_err(anyhow::Error::msg);
            let seed_check = leases.revalidate_seed(module);
            if let Err(error) = lease_check {
                return Err(error).context("rechecking hardened glibc leases after cleanup");
            }
            if let Err(error) = seed_check {
                return Err(error).context("revalidating the provenance seed after cleanup");
            }
            if let Err(error) = validation {
                return Err(error).context("revalidating hardened glibc preparation");
            }
            bail!(
                "hardened discovery oracle is incomplete until PREPARED/DROP/READY/GO validation is installed"
            )
        }
    }
}

fn rediscover_stable_with_helper(helper_path: &Path, module: &Path) -> Result<StableDiscovery> {
    stabilize(module, || rediscover_with_helper(helper_path, module))
}

fn rediscover_with_helper(helper_path: &Path, module: &Path) -> Result<Manifest> {
    let helper = open_trusted_helper(helper_path)?;
    rediscover_from_open_helper(helper, helper_path, module)
}

struct InheritedFd {
    fd: RawFd,
    device: libc::dev_t,
    inode: libc::ino_t,
    kind: libc::mode_t,
}

struct AliasLinkCheck {
    directory: RawFd,
    name: CString,
    link: Vec<u8>,
}

struct HardenedChild<'prepared, 'leases> {
    child: Child,
    _prepared: &'prepared crate::oracle::PreparedGlibc<'leases>,
    reaped: bool,
}

#[allow(dead_code, reason = "driven by the hardened child supervisor in C3.3")]
impl HardenedChild<'_, '_> {
    fn id(&self) -> u32 {
        self.child.id()
    }

    fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.child.stdout.take()
    }

    fn kill_and_wait(&mut self) -> std::io::Result<()> {
        if self.reaped {
            return Ok(());
        }
        if let Ok(pid) = i32::try_from(self.child.id()) {
            // SAFETY: spawn_helper creates a process group whose id is the
            // child pid. SIGKILL is uncatchable and wait reaps the leader.
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        }
        let _ = self.child.kill();
        self.child.wait()?;
        self.reaped = true;
        Ok(())
    }
}

impl Drop for HardenedChild<'_, '_> {
    fn drop(&mut self) {
        let _ = self.kill_and_wait();
    }
}

impl<'leases> crate::oracle::PreparedGlibc<'leases> {
    #[allow(dead_code, reason = "wired to the hardened child supervisor in C3.3")]
    fn spawn_helper<'prepared>(
        &'prepared self,
        module: &Path,
        child_control: BorrowedFd<'_>,
    ) -> Result<HardenedChild<'prepared, 'leases>> {
        let mut command = self.helper_command(module, child_control)?;
        let child = command
            .spawn()
            .context("executing the pinned hardened discovery loader")?;
        Ok(HardenedChild {
            child,
            _prepared: self,
            reaped: false,
        })
    }

    fn helper_command(&self, module: &Path, child_control: BorrowedFd<'_>) -> Result<Command> {
        if !module.is_absolute() {
            bail!("hardened discovery provider path must be absolute");
        }
        self.ensure_leases()?;
        self.revalidate()?;
        self.ensure_leases()?;
        let loader = self.loader_fd()?;
        let helper = self.helper_fd();
        let directory = self.private_directory_fd();
        let child_control = child_control.as_raw_fd();
        let loader_path = format!("/proc/self/fd/{loader}");
        let directory_path = format!("/proc/self/fd/{directory}");
        let helper_path = format!("/proc/self/fd/{helper}");
        let mut command = Command::new(loader_path);
        command
            .arg("--inhibit-cache")
            .arg("--library-path")
            .arg(directory_path)
            .arg(helper_path)
            .arg("--module")
            .arg(module)
            .arg("--control-fd")
            .arg(child_control.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_clear();
        configure_process_group(&mut command);
        let mut inherited = self.runtime_fds().collect::<Vec<_>>();
        inherited.extend([loader, helper, directory, child_control]);
        let aliases = self
            .alias_links()
            .map(|(name, link)| {
                Ok(AliasLinkCheck {
                    directory,
                    name: CString::new(name.as_bytes())
                        .map_err(|_| anyhow!("private glibc alias contains NUL"))?,
                    link: link.as_bytes().to_vec(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        configure_exact_inheritance(&mut command, inherited, aliases)?;
        Ok(command)
    }
}

fn configure_exact_inheritance(
    command: &mut Command,
    mut inherited: Vec<RawFd>,
    aliases: Vec<AliasLinkCheck>,
) -> Result<()> {
    inherited.sort_unstable();
    inherited.dedup();
    let inherited = inherited
        .into_iter()
        .map(|fd| {
            if fd <= libc::STDERR_FILENO || unsafe { libc::fcntl(fd, libc::F_GETFD) } == -1 {
                bail!("hardened discovery inherited fd {fd} is invalid or overlaps stdio");
            }
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(fd, &mut stat) } == -1 {
                return Err(std::io::Error::last_os_error())
                    .context("pinning hardened discovery inherited fd identity");
            }
            Ok(InheritedFd {
                fd,
                device: stat.st_dev,
                inode: stat.st_ino,
                kind: stat.st_mode & libc::S_IFMT,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    for alias in &aliases {
        if !inherited
            .iter()
            .any(|identity| identity.fd == alias.directory)
        {
            bail!(
                "private glibc alias directory fd {} is not inherited",
                alias.directory
            );
        }
    }
    // SAFETY: the closure makes only async-signal-safe Linux syscalls. It runs
    // after the other pre-exec hooks so no later hook can broaden inheritance.
    unsafe {
        command.pre_exec(move || {
            for expected in &inherited {
                let mut stat: libc::stat = std::mem::zeroed();
                if libc::fstat(expected.fd, &mut stat) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if stat.st_dev != expected.device
                    || stat.st_ino != expected.inode
                    || stat.st_mode & libc::S_IFMT != expected.kind
                {
                    return Err(std::io::Error::from_raw_os_error(libc::ESTALE));
                }
            }
            for expected in &aliases {
                let mut link = [0u8; 128];
                let length = libc::readlinkat(
                    expected.directory,
                    expected.name.as_ptr(),
                    link.as_mut_ptr().cast(),
                    link.len(),
                );
                if length == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if length as usize != expected.link.len()
                    || link[..length as usize] != expected.link
                {
                    return Err(std::io::Error::from_raw_os_error(libc::ESTALE));
                }
            }
            if libc::syscall(
                libc::SYS_close_range,
                3u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) == -1
            {
                return Err(std::io::Error::last_os_error());
            }
            for expected in &inherited {
                let flags = libc::fcntl(expected.fd, libc::F_GETFD);
                if flags == -1
                    || libc::fcntl(expected.fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(())
}

fn rediscover_from_open_helper(
    helper: File,
    helper_path: &Path,
    module: &Path,
) -> Result<Manifest> {
    rediscover_from_open_helper_with_timeout(helper, helper_path, module, DISCOVERY_TIMEOUT)
}

fn rediscover_from_open_helper_with_timeout(
    helper: File,
    helper_path: &Path,
    module: &Path,
    timeout: Duration,
) -> Result<Manifest> {
    let helper_fd_path = format!("/proc/self/fd/{}", helper.as_raw_fd());
    let mut command = Command::new(&helper_fd_path);
    command
        .arg("--module")
        .arg(module)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear();
    configure_process_group(&mut command);
    configure_unprivileged(&mut command)?;

    let mut child = command.spawn().with_context(|| {
        format!(
            "executing trusted discovery oracle {}",
            helper_path.display()
        )
    })?;
    let Some(mut stdout) = child.stdout.take() else {
        terminate_oracle(&mut child);
        bail!("discovery oracle stdout was not piped");
    };
    if let Err(error) = set_nonblocking(&stdout) {
        terminate_oracle(&mut child);
        return Err(error).context("making discovery oracle output nonblocking");
    }
    let deadline = Instant::now() + timeout;
    let mut bytes = Vec::new();
    let mut eof = false;
    let mut status = None;
    loop {
        let mut chunk = [0u8; 8192];
        loop {
            match stdout.read(&mut chunk) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(read) => {
                    if let Err(error) = append_bounded(
                        &mut bytes,
                        &chunk[..read],
                        crate::verify::MAX_MANIFEST_BYTES,
                    ) {
                        terminate_oracle(&mut child);
                        return Err(error);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    terminate_oracle(&mut child);
                    return Err(error).context("reading discovery oracle output");
                }
            }
        }
        if status.is_none() {
            status = match child.try_wait() {
                Ok(status) => status,
                Err(error) => {
                    terminate_oracle(&mut child);
                    return Err(error).context("waiting for discovery oracle");
                }
            };
        }
        if eof && status.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            terminate_oracle(&mut child);
            bail!(
                "discovery oracle timed out after {} seconds",
                timeout.as_secs_f64()
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let status = status.expect("loop exits only after the child status is available");
    if !status.success() {
        let code = status
            .code()
            .map(|code| code.to_string())
            .unwrap_or_else(|| format!("signal {}", status.signal().unwrap_or(0)));
        bail!("discovery oracle exited with {code}");
    }
    let manifest: Manifest =
        serde_json::from_slice(&bytes).context("parsing discovery oracle JSON")?;
    if manifest.schema != SCHEMA {
        bail!(
            "discovery oracle schema mismatch: got {:?}, expected {SCHEMA:?}",
            manifest.schema
        );
    }
    Ok(manifest)
}

fn set_nonblocking(file: &impl std::os::fd::AsRawFd) -> std::io::Result<()> {
    // SAFETY: both fcntl calls operate on a live pipe descriptor.
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags == -1
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } == -1
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn configure_process_group(command: &mut Command) {
    // SAFETY: setpgid is async-signal-safe and runs before exec.
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn terminate_oracle(child: &mut Child) {
    if let Ok(pid) = i32::try_from(child.id()) {
        // SAFETY: the child created its own process group whose id is its pid.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn configure_unprivileged(command: &mut Command) -> Result<()> {
    let uid = unsafe { libc::getuid() };
    let euid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getgid() };
    let egid = unsafe { libc::getegid() };
    if euid != 0 && (uid != euid || gid != egid) {
        return Err(anyhow!("refusing discovery with set-id credentials"));
    }
    let ids = (euid == 0).then(|| {
        (
            target_id("SUDO_UID").unwrap_or(65_534),
            target_id("SUDO_GID").unwrap_or(65_534),
        )
    });
    // SAFETY: the closure calls only async-signal-safe Linux syscalls before
    // exec. It either removes every inherited credential or fails the child.
    unsafe {
        command.pre_exec(move || {
            if let Some((target_uid, target_gid)) = ids {
                if libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setresgid(target_gid, target_gid, target_gid) != 0
                    || libc::setresuid(target_uid, target_uid, target_uid) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
            clear_capabilities()?;
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

pub fn run(args: impl Iterator<Item = String>) -> Result<()> {
    let mut helper: Option<PathBuf> = None;
    let mut forwarded: Vec<String> = Vec::new();
    let mut it = args;
    while let Some(a) = it.next() {
        if a == "--helper" {
            let v = it
                .next()
                .ok_or_else(|| anyhow!("--helper requires a value"))?;
            helper = Some(PathBuf::from(v));
        } else if a == "--trusted-workload" {
            eprintln!("unknown argument: --trusted-workload");
            std::process::exit(2);
        } else {
            forwarded.push(a);
        }
    }
    if !forwarded.iter().any(|a| a == "--module") {
        eprintln!("discover requires --module <provider.so>");
        std::process::exit(2);
    }

    let mut searched = Vec::new();
    let path = if let Some(p) = helper {
        // Explicit --helper is authoritative; fail if it doesn't exist.
        searched.push(p.display().to_string());
        if !p.exists() {
            eprintln!(
                "cannot execute discovery helper; searched: {}",
                searched.join(", ")
            );
            std::process::exit(1);
        }
        p
    } else {
        // Without --helper, search: (1) sibling of current_exe(), (2) PATH
        let sibling = std::env::current_exe()
            .ok()
            .and_then(|e| e.parent().map(|d| d.join("p11scope-discover")));

        let sibling_hit = match &sibling {
            Some(p) if p.exists() => Some(p.clone()),
            _ => None,
        };
        if let Some(p) = &sibling {
            searched.push(p.display().to_string());
        }

        if let Some(p) = sibling_hit {
            p
        } else {
            // Actually search PATH, not just claim to: walk each entry,
            // resolve to an absolute path, and only exec that resolved
            // path — never a bare name (no blind PATH exec at runtime).
            let path_hit = std::env::var_os("PATH").and_then(|paths| {
                std::env::split_paths(&paths)
                    .map(|dir| dir.join("p11scope-discover"))
                    .find(|p| p.exists())
            });
            searched.push("p11scope-discover on PATH (searched)".into());
            match path_hit {
                Some(p) => p,
                None => {
                    eprintln!(
                        "cannot execute discovery helper; searched: {}",
                        searched.join(", ")
                    );
                    std::process::exit(1);
                }
            }
        }
    };

    let path = std::fs::canonicalize(&path).map_err(|error| {
        anyhow!(
            "cannot resolve discovery helper {}: {error}",
            path.display()
        )
    })?;
    let mut command = Command::new(&path);
    command.args(&forwarded);
    configure_unprivileged(&mut command)?;
    let status = command.status().map_err(|e| {
        anyhow!(
            "cannot execute discovery helper ({e}); searched: {}",
            searched.join(", ")
        )
    })?;
    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use p11scope_manifest::manifest::{
        Acquisition, ObjectRecord, ProvenanceObject, SurfaceRecord, SurfaceSource, WalkOutcome,
    };
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn oracle_helper_metadata_enforces_owner_mode_and_file_type() {
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("p11scope-discover");
        std::fs::write(&helper, b"ELF").unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
        let metadata = helper.metadata().unwrap();

        validate_helper_metadata(&metadata, metadata.uid()).unwrap();
        assert!(
            validate_helper_metadata(&metadata, metadata.uid().wrapping_add(1))
                .unwrap_err()
                .to_string()
                .contains("owner")
        );

        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o775)).unwrap();
        assert!(
            validate_helper_metadata(&helper.metadata().unwrap(), metadata.uid())
                .unwrap_err()
                .to_string()
                .contains("writable")
        );
        assert!(
            validate_helper_metadata(&dir.path().metadata().unwrap(), metadata.uid())
                .unwrap_err()
                .to_string()
                .contains("regular file")
        );
    }

    #[test]
    fn oracle_output_is_bounded_before_json_parsing() {
        let mut output = vec![b'x'; 16];
        let error = append_bounded(&mut output, b"x", 16).unwrap_err();
        assert!(error.to_string().contains("16-byte limit"), "{error:#}");
        let mut exact = Vec::new();
        append_bounded(&mut exact, &[b'x'; 16], 16).unwrap();
        assert_eq!(exact.len(), 16);
    }

    #[test]
    fn oracle_executes_the_opened_elf_descriptor() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("oracle.c");
        let helper = dir.path().join("p11scope-discover");
        std::fs::write(
            &source,
            r#"#include <stdio.h>
int main(void) {
  puts("{\"schema\":\"p11scope-manifest/4\",\"module_path\":\"/tmp/provider.so\",\"objects\":[],\"provenance_objects\":[],\"interface_list\":{\"status\":\"absent\"},\"surfaces\":[],\"vendor_interfaces\":[],\"alias_groups\":[]}");
  return 0;
}
"#,
        )
        .unwrap();
        assert!(
            Command::new("gcc")
                .args(["-o"])
                .arg(&helper)
                .arg(&source)
                .status()
                .unwrap()
                .success()
        );
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();

        let manifest = rediscover_with_helper(&helper, Path::new("/tmp/provider.so")).unwrap();
        assert_eq!(manifest.schema, SCHEMA);
        assert_eq!(manifest.module_path, "/tmp/provider.so");
    }

    #[test]
    fn authorization_oracle_does_not_receive_observer_environment() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("oracle.c");
        let helper = dir.path().join("p11scope-discover");
        std::fs::write(
            &source,
            r#"#include <stdio.h>
#include <stdlib.h>
int main(void) {
  if (getenv("PATH") || getenv("HOME")) return 91;
  puts("{\"schema\":\"p11scope-manifest/4\",\"module_path\":\"/tmp/provider.so\",\"objects\":[],\"provenance_objects\":[],\"interface_list\":{\"status\":\"absent\"},\"surfaces\":[],\"vendor_interfaces\":[],\"alias_groups\":[]}");
  return 0;
}
"#,
        )
        .unwrap();
        assert!(
            Command::new("gcc")
                .args(["-o"])
                .arg(&helper)
                .arg(&source)
                .status()
                .unwrap()
                .success()
        );
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();

        let manifest = rediscover_with_helper(&helper, Path::new("/tmp/provider.so")).unwrap();
        assert_eq!(manifest.schema, SCHEMA);
    }

    #[test]
    fn authorization_oracle_has_a_hard_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("oracle.c");
        let helper_path = dir.path().join("p11scope-discover");
        let descendant_marker = dir.path().join("descendant-survived");
        std::fs::write(
            &source,
            "#include <fcntl.h>\n#include <unistd.h>\nint main(int argc, char **argv) { if (fork() == 0) { usleep(150000); close(creat(argv[2], 0600)); _exit(0); } sleep(5); return 0; }\n",
        )
        .unwrap();
        assert!(
            Command::new("gcc")
                .args(["-o"])
                .arg(&helper_path)
                .arg(&source)
                .status()
                .unwrap()
                .success()
        );
        std::fs::set_permissions(&helper_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let helper = open_trusted_helper(&helper_path).unwrap();

        let started = std::time::Instant::now();
        let error = rediscover_from_open_helper_with_timeout(
            helper,
            &helper_path,
            &descendant_marker,
            std::time::Duration::from_millis(30),
        )
        .unwrap_err();
        assert!(error.to_string().contains("timed out"), "{error:#}");
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        std::thread::sleep(std::time::Duration::from_millis(250));
        assert!(
            !descendant_marker.exists(),
            "oracle descendant survived timeout"
        );
    }

    #[test]
    fn provenance_module_with_an_existing_writer_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let module = dir.path().join("provider.so");
        std::fs::copy("/bin/true", &module).unwrap();
        let _writer = OpenOptions::new().write(true).open(&module).unwrap();

        let error =
            rediscover_stable_with_helper(&dir.path().join("missing"), &module).unwrap_err();
        assert!(format!("{error:#}").contains("read lease"), "{error:#}");
    }

    #[test]
    fn oracle_path_retarget_cannot_replace_the_opened_helper() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("oracle.c");
        let helper_path = dir.path().join("p11scope-discover");
        std::fs::write(
            &source,
            r#"#include <stdio.h>
int main(void) {
  puts("{\"schema\":\"p11scope-manifest/4\",\"module_path\":\"/tmp/original.so\",\"objects\":[],\"provenance_objects\":[],\"interface_list\":{\"status\":\"absent\"},\"surfaces\":[],\"vendor_interfaces\":[],\"alias_groups\":[]}");
  return 0;
}
"#,
        )
        .unwrap();
        assert!(
            Command::new("gcc")
                .args(["-o"])
                .arg(&helper_path)
                .arg(&source)
                .status()
                .unwrap()
                .success()
        );
        std::fs::set_permissions(&helper_path, std::fs::Permissions::from_mode(0o755)).unwrap();
        let helper = open_trusted_helper(&helper_path).unwrap();
        std::fs::remove_file(&helper_path).unwrap();
        std::fs::copy("/bin/false", &helper_path).unwrap();

        let manifest =
            rediscover_from_open_helper(helper, &helper_path, Path::new("/tmp/original.so"))
                .unwrap();
        assert_eq!(manifest.module_path, "/tmp/original.so");
    }

    fn closure_manifest(module: &Path, paths: &[&Path]) -> Manifest {
        let identity = p11scope_manifest::identity::identify(module);
        Manifest {
            schema: SCHEMA.into(),
            module_path: module.display().to_string(),
            objects: vec![ObjectRecord {
                id: 0,
                path: module.display().to_string(),
                identity,
            }],
            provenance_objects: paths
                .iter()
                .map(|path| current_provenance_object(path).unwrap().0)
                .collect::<Vec<ProvenanceObject>>(),
            interface_list: Acquisition::Absent,
            surfaces: vec![SurfaceRecord {
                source: SurfaceSource::LegacyFunctionList,
                acquisition: Acquisition::Absent,
                version: None,
                walk: WalkOutcome::NotWalked,
                functions: vec![],
            }],
            vendor_interfaces: vec![],
            alias_groups: vec![],
        }
    }

    #[test]
    fn new_dependency_is_not_authorized_until_a_preleased_retry() {
        let dir = tempfile::tempdir().unwrap();
        let module = dir.path().join("module.so");
        let dependency = dir.path().join("dependency.so");
        std::fs::copy("/bin/true", &module).unwrap();
        std::fs::copy("/bin/false", &dependency).unwrap();
        let passes = [
            closure_manifest(&module, &[&module]),
            closure_manifest(&module, &[&module, &dependency]),
            closure_manifest(&module, &[&module, &dependency]),
        ];
        let mut count = 0;

        let stable = stabilize(&module, || {
            let manifest = passes[count].clone();
            count += 1;
            Ok(manifest)
        })
        .unwrap();

        assert_eq!(count, 3);
        assert_eq!(stable.manifest().provenance_objects.len(), 2);
    }

    #[test]
    fn byte_identical_replacement_inode_forces_a_retry() {
        let dir = tempfile::tempdir().unwrap();
        let module = dir.path().join("module.so");
        let first = dir.path().join("first.so");
        let replacement = dir.path().join("replacement.so");
        std::fs::copy("/bin/true", &module).unwrap();
        std::fs::copy("/bin/false", &first).unwrap();
        std::fs::copy(&first, &replacement).unwrap();
        assert_eq!(
            p11scope_manifest::identity::identify(&first).sha256,
            p11scope_manifest::identity::identify(&replacement).sha256
        );
        assert_ne!(
            first.metadata().unwrap().ino(),
            replacement.metadata().unwrap().ino()
        );
        let passes = [
            closure_manifest(&module, &[&module, &first]),
            closure_manifest(&module, &[&module, &replacement]),
            closure_manifest(&module, &[&module, &replacement]),
        ];
        let mut count = 0;

        stabilize(&module, || {
            let manifest = passes[count].clone();
            count += 1;
            Ok(manifest)
        })
        .unwrap();

        assert_eq!(count, 3);
    }

    #[test]
    fn alternating_inode_closure_exhausts_the_pass_bound() {
        let dir = tempfile::tempdir().unwrap();
        let module = dir.path().join("module.so");
        let first = dir.path().join("first.so");
        let second = dir.path().join("second.so");
        std::fs::copy("/bin/true", &module).unwrap();
        std::fs::copy("/bin/false", &first).unwrap();
        std::fs::copy(&first, &second).unwrap();
        let manifests = [
            closure_manifest(&module, &[&module, &first]),
            closure_manifest(&module, &[&module, &second]),
        ];
        let mut count = 0;

        let error = stabilize(&module, || {
            let manifest = manifests[count % 2].clone();
            count += 1;
            Ok(manifest)
        })
        .unwrap_err();

        assert_eq!(count, 8);
        assert!(error.to_string().contains("did not stabilize"), "{error:#}");
    }

    #[test]
    fn seed_path_replacement_invalidates_the_stable_result() {
        let dir = tempfile::tempdir().unwrap();
        let module = dir.path().join("module.so");
        let replacement = dir.path().join("replacement.so");
        std::fs::copy("/bin/true", &module).unwrap();
        std::fs::copy("/bin/false", &replacement).unwrap();
        let manifest = closure_manifest(&module, &[&module]);

        let stable = stabilize(&module, || Ok(manifest.clone())).unwrap();
        std::fs::rename(&replacement, &module).unwrap();

        let error = stable.ensure_stable().unwrap_err();
        assert!(error.to_string().contains("was replaced"), "{error:#}");
    }

    #[test]
    fn hardened_influences_use_the_closure_lease_monitor_and_fd_store() {
        let dir = tempfile::tempdir().unwrap();
        let module = dir.path().join("module.so");
        let runtime = dir.path().join("runtime.so");
        std::fs::copy("/bin/true", &module).unwrap();
        std::fs::copy("/bin/false", &runtime).unwrap();
        let mut leases = ClosureLeases::new(&module).unwrap();

        let fd = leases
            .retain_influence(std::fs::File::open(&runtime).unwrap(), "glibc runtime")
            .unwrap();

        assert!(fd > 2);
        assert_eq!(
            mapping_file_key(leases.file(fd).unwrap()).unwrap(),
            mapping_file_key(&std::fs::File::open(&runtime).unwrap()).unwrap()
        );
        leases.ensure().unwrap();
    }

    #[test]
    fn hardened_lease_break_can_be_taken_without_process_exit() {
        let dir = tempfile::tempdir().unwrap();
        let module = dir.path().join("module.so");
        let runtime = dir.path().join("runtime.so");
        std::fs::copy("/bin/true", &module).unwrap();
        std::fs::copy("/bin/false", &runtime).unwrap();
        let mut leases = ClosureLeases::new(&module).unwrap();
        let fd = leases
            .retain_influence(std::fs::File::open(&runtime).unwrap(), "glibc runtime")
            .unwrap();

        #[repr(C)]
        struct LeaseOwner {
            kind: libc::c_int,
            pid: libc::pid_t,
        }
        const F_OWNER_TID: libc::c_int = 0;
        const F_SETOWN_EX: libc::c_int = 15;
        // Libtest has other threads whose signal masks we do not own. Route
        // this real break to the current blocked test thread; production uses
        // process-directed SIGIO only after its single-thread gate.
        let owner = LeaseOwner {
            kind: F_OWNER_TID,
            pid: unsafe { libc::syscall(libc::SYS_gettid) as libc::pid_t },
        };
        assert_eq!(unsafe { libc::fcntl(fd, F_SETOWN_EX, &owner) }, 0);

        let mut writer = Command::new("/bin/sh")
            .arg("-c")
            .arg("exec 3>\"$1\"")
            .arg("sh")
            .arg(&runtime)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut event = libc::pollfd {
            fd: leases.event_fd().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut event, 1, 1_000) }, 1);
        assert_ne!(event.revents & libc::POLLIN, 0);
        assert!(leases.take_break().unwrap());
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETLEASE, libc::F_UNLCK) },
            0
        );
        assert!(writer.wait().unwrap().success());
    }

    #[test]
    fn exact_inheritance_sweeps_every_unlisted_fd_at_exec() {
        use std::os::unix::process::CommandExt as _;

        let allowed = std::fs::File::open("/bin/true").unwrap();
        let forbidden = std::fs::File::open("/bin/false").unwrap();
        assert!(allowed.as_raw_fd() > 2 && forbidden.as_raw_fd() > 2);
        let forbidden_fd = forbidden.as_raw_fd();
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("printf R; kill -STOP $$")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .env_clear();
        // SAFETY: this test hook uses async-signal-safe fcntl calls and runs
        // before the production exact-inheritance hook.
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(forbidden_fd, libc::F_GETFD);
                if flags == -1
                    || libc::fcntl(forbidden_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) == -1
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        configure_exact_inheritance(&mut command, vec![allowed.as_raw_fd()], Vec::new()).unwrap();

        let mut child = command.spawn().unwrap();
        let mut readable = libc::pollfd {
            fd: child.stdout.as_ref().unwrap().as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready_event = unsafe { libc::poll(&mut readable, 1, 5_000) };
        if ready_event != 1 {
            let _ = child.kill();
            let _ = child.wait();
        }
        assert_eq!(ready_event, 1, "child did not reach the post-exec barrier");
        let mut ready = [0u8; 1];
        child
            .stdout
            .as_mut()
            .unwrap()
            .read_exact(&mut ready)
            .unwrap();
        assert_eq!(ready, *b"R");
        let actual = std::fs::read_dir(format!("/proc/{}/fd", child.id()))
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .parse::<RawFd>()
                    .unwrap()
            })
            .collect::<BTreeSet<_>>();
        child.kill().unwrap();
        child.wait().unwrap();

        assert_eq!(actual, BTreeSet::from([0, 1, 2, allowed.as_raw_fd()]));
        assert!(!actual.contains(&forbidden_fd));
    }

    #[test]
    fn cloexec_sweep_preserves_rusts_exec_error_pipe() {
        let allowed = std::fs::File::open("/bin/true").unwrap();
        let mut command = Command::new("/definitely/missing");
        configure_exact_inheritance(&mut command, vec![allowed.as_raw_fd()], Vec::new()).unwrap();

        let error = command.spawn().unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ENOENT));
    }

    #[test]
    fn post_fork_fd_substitution_is_rejected_before_exec() {
        use std::os::unix::process::CommandExt as _;

        let allowed = std::fs::File::open("/bin/true").unwrap();
        let replacement = std::fs::File::open("/bin/false").unwrap();
        let allowed_fd = allowed.as_raw_fd();
        let replacement_fd = replacement.as_raw_fd();
        let mut command = Command::new("/bin/true");
        // SAFETY: dup2 is async-signal-safe and deliberately mutates only the
        // child fd table before the production identity check.
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(replacement_fd, allowed_fd) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        configure_exact_inheritance(&mut command, vec![allowed_fd], Vec::new()).unwrap();

        let error = command.spawn().unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ESTALE));
    }

    #[test]
    fn post_fork_alias_retarget_is_rejected_before_exec() {
        let dir = tempfile::tempdir().unwrap();
        let directory = std::fs::File::open(dir.path()).unwrap();
        let target = std::fs::File::open("/bin/true").unwrap();
        let replacement = std::fs::File::open("/bin/false").unwrap();
        let alias = dir.path().join("libc.so.6");
        let expected_link = format!("/proc/self/fd/{}", target.as_raw_fd());
        std::os::unix::fs::symlink(&expected_link, &alias).unwrap();
        let mut command = Command::new("/bin/true");
        configure_exact_inheritance(
            &mut command,
            vec![directory.as_raw_fd(), target.as_raw_fd()],
            vec![AliasLinkCheck {
                directory: directory.as_raw_fd(),
                name: CString::new("libc.so.6").unwrap(),
                link: expected_link.into_bytes(),
            }],
        )
        .unwrap();
        std::fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(format!("/proc/self/fd/{}", replacement.as_raw_fd()), &alias)
            .unwrap();

        let error = command.spawn().unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ESTALE));
    }

    #[test]
    fn hardened_glibc_preflight_leases_revalidates_and_cleans_test_root() {
        use std::os::fd::AsFd as _;

        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        for directory in [
            "opt",
            "lib64",
            "usr",
            "usr/lib",
            "usr/lib/x86_64-linux-gnu",
            "usr/lib64",
            "etc",
            "run",
        ] {
            std::fs::create_dir(root.path().join(directory)).unwrap();
            std::fs::set_permissions(
                root.path().join(directory),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        let helper = root.path().join("opt/p11scope-discover");
        let module = root.path().join("opt/provider.so");
        let interpreter = root.path().join("lib64/ld-linux-x86-64.so.2");
        let libc = root.path().join("usr/lib/x86_64-linux-gnu/libc.so.6");
        let helper_source = root.path().join("opt/p11scope-discover.c");
        std::fs::write(
            &helper_source,
            r#"
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv, char **envp) {
    int envc = 0;
    while (envp[envc] != NULL) envc++;
    if (dprintf(1, "argc=%d\n", argc) < 0) return 2;
    for (int i = 0; i < argc; i++) {
        if (dprintf(1, "arg%d=%s\n", i, argv[i]) < 0) return 2;
    }
    if (dprintf(1, "envc=%d\npid=%ld\npgid=%ld\nSTOP\n",
                envc, (long)getpid(), (long)getpgrp()) < 0) return 2;
    if (raise(SIGSTOP) != 0) return 3;
    return 0;
}
"#,
        )
        .unwrap();
        let compiled = Command::new("gcc")
            .args(["-O2", "-Wall", "-Werror", "-o"])
            .arg(&helper)
            .arg(&helper_source)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        std::fs::copy("/bin/false", &module).unwrap();
        std::fs::copy("/lib64/ld-linux-x86-64.so.2", &interpreter).unwrap();
        std::fs::copy("/usr/lib/x86_64-linux-gnu/libc.so.6", &libc).unwrap();
        std::fs::hard_link(
            &interpreter,
            root.path()
                .join("usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"),
        )
        .unwrap();
        for file in [&helper, &module, &interpreter, &libc] {
            std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let owner = unsafe { libc::geteuid() };
        let mut leases = ClosureLeases::new(&module).unwrap();

        let mut prepared = crate::oracle::prepare_glibc_test_root(
            root.path(),
            Path::new("/opt/p11scope-discover"),
            owner,
            &mut leases,
        )
        .unwrap();

        let mut controls = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    controls.as_mut_ptr(),
                )
            },
            0
        );
        let parent_control = unsafe { std::os::fd::OwnedFd::from_raw_fd(controls[0]) };
        let child_control = unsafe { std::os::fd::OwnedFd::from_raw_fd(controls[1]) };
        assert!(parent_control.as_raw_fd() > 2 && child_control.as_raw_fd() > 2);
        let mut expected_fds = BTreeSet::from([
            0,
            1,
            2,
            prepared.helper_fd(),
            prepared.loader_fd().unwrap(),
            prepared.private_directory_fd(),
            child_control.as_raw_fd(),
        ]);
        expected_fds.extend(prepared.runtime_fds());
        let event_fd = prepared.lease_event_fd().as_raw_fd();
        let helper_fd = prepared.helper_fd();
        let control_fd = child_control.as_raw_fd();
        let mut child = prepared
            .spawn_helper(&module, child_control.as_fd())
            .unwrap();
        let pid = child.id();
        let mut stdout = child.take_stdout().unwrap();
        set_nonblocking(&stdout).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut output = Vec::new();
        while !output.ends_with(b"STOP\n") {
            let mut bytes = [0u8; 512];
            match stdout.read(&mut bytes) {
                Ok(0) => break,
                Ok(read) => output.extend_from_slice(&bytes[..read]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        child.kill_and_wait().unwrap();
                        panic!("hardened helper did not reach its stop barrier");
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("reading hardened helper facts failed: {error}"),
            }
        }
        let mut status = 0;
        let stopped = loop {
            let waited = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WUNTRACED) };
            if waited == pid as libc::pid_t {
                break libc::WIFSTOPPED(status);
            }
            if waited == -1
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
            {
                continue;
            }
            break false;
        };
        assert!(
            stopped,
            "hardened helper did not stop after reporting facts"
        );
        let expected_output = format!(
            "argc=5\narg0=/proc/self/fd/{helper_fd}\narg1=--module\narg2={}\narg3=--control-fd\narg4={control_fd}\nenvc=0\npid={pid}\npgid={pid}\nSTOP\n",
            module.display()
        );
        assert_eq!(String::from_utf8(output).unwrap(), expected_output);
        assert_eq!(
            unsafe { libc::getpgid(pid as libc::pid_t) },
            pid as libc::pid_t
        );
        let actual_fds = std::fs::read_dir(format!("/proc/{pid}/fd"))
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .parse::<RawFd>()
                    .unwrap()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(actual_fds, expected_fds);
        assert!(!actual_fds.contains(&parent_control.as_raw_fd()));
        assert!(!actual_fds.contains(&event_fd));
        drop(child);
        let mut reaped_status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid as libc::pid_t, &mut reaped_status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );

        prepared.revalidate().unwrap();
        std::fs::write(root.path().join("etc/ld.so.preload"), []).unwrap();
        let error = prepared.revalidate().unwrap_err();
        assert!(error.to_string().contains("appeared"), "{error:#}");
        std::fs::remove_file(root.path().join("etc/ld.so.preload")).unwrap();
        prepared.revalidate().unwrap();
        prepared.cleanup().unwrap();
        drop(prepared);
        leases.ensure().unwrap();
        assert_eq!(
            std::fs::read_dir(root.path().join("run/p11scope"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn hardened_selection_preflights_instead_of_routing_to_legacy() {
        let error = rediscover_stable_selected(
            Path::new("/missing/p11scope-discover"),
            Path::new("/missing/provider.so"),
            &crate::oracle::OracleSelection::hardened_without_target_for_test(),
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("opening discovery oracle helper"),
            "{error:#}"
        );
        assert!(
            !error
                .to_string()
                .contains("hardened discovery oracle is incomplete")
        );
    }

    #[test]
    fn hardened_stage_is_cleaned_before_lease_check_and_c3_refusal() {
        let source = include_str!("discover_cmd.rs");
        let production = &source[..source.find("#[cfg(test)]").unwrap()];
        let start = production
            .find("let mut prepared = crate::oracle::prepare_glibc")
            .unwrap();
        let block = &production[start..];
        let prepared_statement = block.find(';').unwrap() + 1;
        let validation = block
            .find("let validation = prepared.revalidate();")
            .unwrap();
        let cleanup = block.find("let cleanup = prepared.cleanup();").unwrap();
        let drop_guard = block.find("drop(prepared);").unwrap();
        let ensure = block.find("leases.ensure()").unwrap();
        let seed = block.find("leases.revalidate_seed(module)").unwrap();
        let saved_validation = block.find("if let Err(error) = validation").unwrap();
        let refusal = block
            .find("hardened discovery oracle is incomplete")
            .unwrap();

        assert!(validation < cleanup && cleanup < drop_guard);
        assert!(drop_guard < ensure && ensure < seed);
        assert!(seed < saved_validation && saved_validation < refusal);
        assert!(!block[prepared_statement..drop_guard].contains('?'));
        assert!(!block[prepared_statement..drop_guard].contains("leases.ensure"));
    }
}
