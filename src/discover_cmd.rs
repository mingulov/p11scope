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
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::os::unix::process::CommandExt as _;
use std::os::unix::process::ExitStatusExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
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

#[allow(dead_code, reason = "private one-pass seam awaiting C3.3B wiring")]
fn validate_hardened_executable_maps(
    bytes: &[u8],
    expected: &BTreeSet<MappingFileKey>,
    provider: MappingFileKey,
) -> Result<()> {
    let maps = p11scope_manifest::maps::parse_maps(bytes).map_err(anyhow::Error::msg)?;
    let actual = p11scope_manifest::maps::executable_file_keys(&maps);
    if actual.contains(&provider) {
        bail!("provider was executable before hardened discovery GO");
    }
    if actual != *expected {
        bail!("hardened discovery executable mappings differ from the authorized closure");
    }
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
        leases.ensure().map_err(anyhow::Error::msg)?;
        Ok(leases)
    }

    fn retain_reported(&mut self, record: &ProvenanceObject) -> Result<()> {
        self.retain_reported_inner(record)?;
        self.ensure().map_err(anyhow::Error::msg)
    }

    pub(crate) fn retain_reported_nonexiting(&mut self, record: &ProvenanceObject) -> Result<bool> {
        self.retain_reported_inner(record)?;
        self.take_break().map_err(anyhow::Error::msg)
    }

    fn retain_reported_inner(&mut self, record: &ProvenanceObject) -> Result<()> {
        let key = record_key(record);
        if let Some(retained) = self.objects.get(&key) {
            if !same_identity(&retained.identity, &record.identity) {
                bail!("provenance mapping {key:?} changed whole-file identity between passes");
            }
            return Ok(());
        }
        for influence in &self.influences {
            if mapping_file_key(influence).map_err(anyhow::Error::msg)? != key {
                continue;
            }
            let identity = inspect_file(influence)
                .map_err(anyhow::Error::msg)
                .with_context(|| {
                    format!(
                        "identifying retained hardened influence for {}",
                        record.path
                    )
                })?
                .identity;
            if !same_identity(&identity, &record.identity) {
                bail!(
                    "provenance mapping {} changed whole-file identity between preparation and discovery",
                    record.path
                );
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
        Ok(())
    }

    fn keys(&self) -> BTreeSet<MappingFileKey> {
        self.objects.keys().copied().collect()
    }

    pub(crate) fn stabilization_keys(&self) -> Result<BTreeSet<MappingFileKey>> {
        let mut keys = self.keys();
        for influence in &self.influences {
            keys.insert(mapping_file_key(influence).map_err(anyhow::Error::msg)?);
        }
        Ok(keys)
    }

    pub(crate) fn seed_key(&self) -> MappingFileKey {
        self.seed
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

    pub(crate) fn revalidate_seed(&self, module: &Path) -> Result<()> {
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

fn stabilize_hardened<'leases>(
    module: &Path,
    selection: &OracleSelection,
    prepared: &mut crate::oracle::PreparedGlibc<'leases>,
    mut pass: impl FnMut(&crate::oracle::PreparedGlibc<'leases>) -> Result<HardenedPassOutcome>,
) -> Result<HardenedPassOutcome> {
    let mut previous = None;
    for _ in 0..MAX_STABILIZATION_PASSES {
        selection.revalidate()?;
        prepared.revalidate()?;
        prepared.revalidate_seed(module)?;
        if prepared.take_lease_break().map_err(anyhow::Error::msg)? {
            return Ok(HardenedPassOutcome::LeaseBroken);
        }
        let preleased = prepared.stabilization_keys()?;
        let HardenedPassOutcome::Complete(manifest) = pass(prepared)? else {
            return Ok(HardenedPassOutcome::LeaseBroken);
        };
        let current = closure_keys(&manifest)?;
        if !current.contains(&prepared.seed_key()) {
            bail!("discovery pass omitted the selected provenance module mapping");
        }
        selection.revalidate()?;
        prepared.revalidate()?;
        prepared.revalidate_seed(module)?;
        if prepared.take_lease_break().map_err(anyhow::Error::msg)? {
            return Ok(HardenedPassOutcome::LeaseBroken);
        }
        let already_leased = current.is_subset(&preleased);
        for object in &manifest.provenance_objects {
            if prepared.retain_reported_nonexiting(object)? {
                return Ok(HardenedPassOutcome::LeaseBroken);
            }
        }
        selection.revalidate()?;
        prepared.revalidate()?;
        prepared.revalidate_seed(module)?;
        if already_leased && previous.as_ref() == Some(&current) {
            return Ok(HardenedPassOutcome::Complete(manifest));
        }
        previous = Some(current);
    }
    bail!("provenance closure did not stabilize within {MAX_STABILIZATION_PASSES} discovery passes")
}

fn finalize_hardened_prepared<'leases>(
    mut prepared: crate::oracle::PreparedGlibc<'leases>,
    stabilization: Result<HardenedPassOutcome>,
) -> Result<(Result<()>, Result<HardenedPassOutcome>)> {
    let validation = prepared.revalidate();
    let cleanup = prepared.cleanup();
    drop(prepared);
    cleanup.context("cleaning hardened glibc preparation")?;
    if matches!(&stabilization, Ok(HardenedPassOutcome::LeaseBroken)) {
        crate::verify::object_changed_exit();
    }
    Ok((validation, stabilization))
}

fn finish_hardened(
    module: &Path,
    leases: ClosureLeases,
    finalized: (Result<()>, Result<HardenedPassOutcome>),
) -> Result<StableDiscovery> {
    let lease_check = leases.ensure().map_err(anyhow::Error::msg);
    let seed_check = leases.revalidate_seed(module);
    let (validation, stabilization) = finalized;
    lease_check.context("rechecking hardened glibc leases after cleanup")?;
    seed_check.context("revalidating the provenance seed after cleanup")?;
    validation.context("revalidating hardened glibc preparation")?;
    match stabilization? {
        HardenedPassOutcome::Complete(manifest) => Ok(StableDiscovery {
            manifest,
            leases,
            module: module.to_path_buf(),
        }),
        HardenedPassOutcome::LeaseBroken => {
            unreachable!("lease breaks exit while finalizing hardened preparation")
        }
    }
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
            let stabilization = stabilize_hardened(module, selection, &mut prepared, |prepared| {
                run_hardened_pass(selection, prepared, module, DISCOVERY_TIMEOUT)
            });
            let finalized = finalize_hardened_prepared(prepared, stabilization)?;
            finish_hardened(module, leases, finalized)
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
    pidfd: Option<OwnedFd>,
    _prepared: &'prepared crate::oracle::PreparedGlibc<'leases>,
    status: Option<ExitStatus>,
}

#[allow(dead_code, reason = "driven by the hardened child supervisor in C3.3")]
impl HardenedChild<'_, '_> {
    fn id(&self) -> u32 {
        self.child.id()
    }

    fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.child.stdout.take()
    }

    fn pidfd(&self) -> &OwnedFd {
        self.pidfd
            .as_ref()
            .expect("spawn returns only after opening the child pidfd")
    }

    fn terminate_and_wait(&mut self) -> Result<()> {
        if self.status.is_some() {
            return Ok(());
        }
        let pid = i32::try_from(self.child.id())
            .map_err(|_| anyhow!("hardened discovery child PID is out of range"))?;
        // SAFETY: spawn_helper creates a process group whose id is the child
        // pid. SIGKILL is uncatchable and the guard reaps the leader below.
        let mut failure = None;
        if unsafe { libc::kill(-pid, libc::SIGKILL) } == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                failure = Some(anyhow!(
                    "killing hardened discovery process group failed: {error}"
                ));
            }
        }
        if let Some(pidfd) = &self.pidfd {
            if let Err(error) = crate::verify::pidfd_send_signal(pidfd, libc::SIGKILL) {
                let _ = self.child.kill();
                if !error.contains("No such process") {
                    failure.get_or_insert_with(|| anyhow!(error));
                }
            }
            if let Err(error) = crate::verify::wait_pidfd(pidfd) {
                failure.get_or_insert_with(|| anyhow!(error));
            }
        } else {
            let _ = self.child.kill();
        }
        let status = self
            .child
            .wait()
            .context("reaping hardened discovery child")?;
        self.status = Some(status);
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn status(&self) -> Option<ExitStatus> {
        self.status
    }
}

impl Drop for HardenedChild<'_, '_> {
    fn drop(&mut self) {
        let _ = self.terminate_and_wait();
    }
}

impl<'leases> crate::oracle::PreparedGlibc<'leases> {
    #[allow(dead_code, reason = "wired to the hardened child supervisor in C3.3")]
    fn spawn_helper<'prepared>(
        &'prepared self,
        module: &Path,
        child_control: OwnedFd,
    ) -> Result<HardenedChild<'prepared, 'leases>> {
        let mut command = self.helper_command(module, child_control.as_fd())?;
        let child = command
            .spawn()
            .context("executing the pinned hardened discovery loader")?;
        drop(child_control);
        let mut child = HardenedChild {
            child,
            pidfd: None,
            _prepared: self,
            status: None,
        };
        let pid = libc::pid_t::try_from(child.id())
            .map_err(|_| anyhow!("hardened discovery child PID is out of range"))?;
        child.pidfd =
            Some(crate::verify::pidfd_open(pid).context("opening hardened discovery child pidfd")?);
        Ok(child)
    }

    fn helper_command(&self, module: &Path, child_control: BorrowedFd<'_>) -> Result<Command> {
        if !module.is_absolute() {
            bail!("hardened discovery provider path must be absolute");
        }
        self.revalidate()?;
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

#[allow(dead_code, reason = "private one-pass seam awaiting C3.3B wiring")]
#[derive(Debug)]
enum HardenedPassOutcome {
    Complete(Manifest),
    LeaseBroken,
}

#[allow(dead_code, reason = "private one-pass seam awaiting C3.3B wiring")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum HardenedProtocolState {
    Prepared,
    Ready,
    Running,
}

#[allow(dead_code, reason = "private one-pass seam awaiting C3.3B wiring")]
fn fd_identity(fd: RawFd) -> Result<crate::oracle::ProcFdIdentity> {
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } == -1 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("identifying hardened discovery fd {fd}"));
    }
    Ok(crate::oracle::ProcFdIdentity {
        device: stat.st_dev,
        inode: stat.st_ino,
        kind: stat.st_mode & libc::S_IFMT,
    })
}

#[allow(dead_code, reason = "private one-pass seam awaiting C3.3B wiring")]
fn make_control_pair() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } == -1
    {
        return Err(std::io::Error::last_os_error())
            .context("creating hardened discovery control socketpair");
    }
    let parent = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let child = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    Ok((
        crate::oracle::normalize_owned_fd(parent)?,
        crate::oracle::normalize_owned_fd(child)?,
    ))
}

#[allow(dead_code, reason = "private one-pass seam awaiting C3.3B wiring")]
fn send_control(fd: &OwnedFd, packet: &[u8]) -> Result<()> {
    let sent = unsafe {
        libc::send(
            fd.as_raw_fd(),
            packet.as_ptr().cast(),
            packet.len(),
            libc::MSG_NOSIGNAL,
        )
    };
    if sent != packet.len() as isize {
        return Err(if sent == -1 {
            std::io::Error::last_os_error().into()
        } else {
            anyhow!("hardened discovery control packet was partially sent")
        });
    }
    Ok(())
}

#[allow(dead_code, reason = "private one-pass seam awaiting C3.3B wiring")]
enum ControlPacket {
    None,
    Eof,
    Packet(Vec<u8>),
}

#[allow(dead_code, reason = "private one-pass seam awaiting C3.3B wiring")]
fn receive_control(fd: &OwnedFd) -> Result<ControlPacket> {
    let mut bytes = [0u8; 32];
    let received = unsafe {
        libc::recv(
            fd.as_raw_fd(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
            libc::MSG_DONTWAIT | libc::MSG_TRUNC,
        )
    };
    if received == 0 {
        return Ok(ControlPacket::Eof);
    }
    if received == -1 {
        let error = std::io::Error::last_os_error();
        return if matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
        ) {
            Ok(ControlPacket::None)
        } else {
            Err(error).context("receiving hardened discovery control packet")
        };
    }
    let received = usize::try_from(received)
        .map_err(|_| anyhow!("invalid hardened discovery control packet length"))?;
    if received > bytes.len() {
        bail!("hardened discovery control packet exceeds 32 bytes");
    }
    Ok(ControlPacket::Packet(bytes[..received].to_vec()))
}

#[allow(dead_code, reason = "private one-pass seam awaiting C3.3B wiring")]
fn bounded_read(mut file: &File, limit: u64, label: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.by_ref()
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {label}"))?;
    if bytes.len() as u64 > limit {
        bail!("{label} exceeds the {limit}-byte limit");
    }
    Ok(bytes)
}

#[allow(dead_code, reason = "private one-pass seam awaiting C3.3B wiring")]
fn poll_timeout(deadline: Instant) -> Result<libc::c_int> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| anyhow!("hardened discovery oracle reached its absolute deadline"))?;
    let millis = remaining.as_millis().saturating_add(1);
    Ok(millis.min(libc::c_int::MAX as u128) as libc::c_int)
}

#[allow(dead_code, reason = "private one-pass seam awaiting C3.3B wiring")]
fn run_hardened_pass(
    selection: &OracleSelection,
    prepared: &crate::oracle::PreparedGlibc<'_>,
    module: &Path,
    timeout: Duration,
) -> Result<HardenedPassOutcome> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| anyhow!("hardened discovery deadline overflow"))?;
    if prepared.take_lease_break().map_err(anyhow::Error::msg)? {
        return Ok(HardenedPassOutcome::LeaseBroken);
    }
    let (parent_control, child_control) = make_control_pair()?;
    set_nonblocking(&parent_control)?;
    let child_control_fd = child_control.as_raw_fd();
    let child_control_identity = fd_identity(child_control.as_raw_fd())?;
    let mut child = prepared.spawn_helper(module, child_control)?;
    poll_timeout(deadline)?;
    let pid = child.id();
    let mut stdout = child
        .take_stdout()
        .ok_or_else(|| anyhow!("hardened discovery stdout was not piped"))?;
    set_nonblocking(&stdout)?;

    let null = File::open("/dev/null").context("opening /dev/null identity")?;
    let mut expected_fds = BTreeMap::from([
        (0, fd_identity(null.as_raw_fd())?),
        (1, fd_identity(stdout.as_raw_fd())?),
        (2, fd_identity(null.as_raw_fd())?),
    ]);
    expected_fds.insert(prepared.helper_fd(), fd_identity(prepared.helper_fd())?);
    expected_fds.insert(prepared.loader_fd()?, fd_identity(prepared.loader_fd()?)?);
    expected_fds.insert(
        prepared.private_directory_fd(),
        fd_identity(prepared.private_directory_fd())?,
    );
    for fd in prepared.runtime_fds() {
        expected_fds.insert(fd, fd_identity(fd)?);
    }
    expected_fds.insert(child_control_fd, child_control_identity);
    if child_control_fd <= 2 {
        bail!("hardened child control fd overlaps stdio");
    }

    let provider = prepared.seed_key();
    let mut executable = BTreeSet::from([prepared.file_key(prepared.helper_fd())?]);
    for fd in prepared.runtime_fds() {
        executable.insert(prepared.file_key(fd)?);
    }
    let loader = prepared.file_key(prepared.loader_fd()?)?;
    let mut state = HardenedProtocolState::Prepared;
    let mut process = None;
    let mut maps = None;
    let mut self_memory = None;
    let mut output = Vec::new();
    let mut stdout_eof = false;
    let mut control_eof = false;
    let mut child_exited = false;

    loop {
        if prepared.take_lease_break().map_err(anyhow::Error::msg)? {
            child.terminate_and_wait()?;
            return Ok(HardenedPassOutcome::LeaseBroken);
        }

        let mut chunk = [0u8; 8192];
        loop {
            match stdout.read(&mut chunk) {
                Ok(0) => {
                    stdout_eof = true;
                    break;
                }
                Ok(read) => append_bounded(
                    &mut output,
                    &chunk[..read],
                    crate::verify::MAX_MANIFEST_BYTES,
                )?,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error).context("reading hardened discovery stdout"),
            }
        }

        if state == HardenedProtocolState::Running && child_exited && stdout_eof {
            child.terminate_and_wait()?;
            let status = child.status().expect("termination always caches status");
            if !status.success() {
                let code = status
                    .code()
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| format!("signal {}", status.signal().unwrap_or(0)));
                bail!("hardened discovery oracle exited with {code}");
            }
            poll_timeout(deadline)?;
            let manifest: Manifest =
                serde_json::from_slice(&output).context("parsing hardened discovery JSON")?;
            if manifest.schema != SCHEMA {
                bail!(
                    "hardened discovery schema mismatch: got {:?}, expected {SCHEMA:?}",
                    manifest.schema
                );
            }
            if prepared.take_lease_break().map_err(anyhow::Error::msg)? {
                return Ok(HardenedPassOutcome::LeaseBroken);
            }
            selection.revalidate()?;
            prepared.revalidate()?;
            prepared.revalidate_seed(module)?;
            if prepared.take_lease_break().map_err(anyhow::Error::msg)? {
                return Ok(HardenedPassOutcome::LeaseBroken);
            }
            poll_timeout(deadline)?;
            return Ok(HardenedPassOutcome::Complete(manifest));
        }

        let mut pollfds = [
            libc::pollfd {
                fd: if control_eof {
                    -1
                } else {
                    parent_control.as_raw_fd()
                },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if stdout_eof { -1 } else { stdout.as_raw_fd() },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if child_exited {
                    -1
                } else {
                    child.pidfd().as_raw_fd()
                },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: prepared.lease_event_fd().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let polled = loop {
            let timeout = poll_timeout(deadline)?;
            let result = unsafe { libc::poll(pollfds.as_mut_ptr(), pollfds.len() as _, timeout) };
            if result >= 0 {
                break result;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error).context("polling hardened discovery child");
            }
        };
        if polled == 0 {
            bail!("hardened discovery oracle reached its absolute deadline");
        }
        if pollfds[2].revents & libc::POLLIN != 0 {
            child_exited = true;
            if state != HardenedProtocolState::Running {
                bail!("hardened discovery child exited before GO");
            }
        }
        if pollfds[3].revents != 0 {
            continue;
        }
        if pollfds[0].revents != 0 {
            match receive_control(&parent_control)? {
                ControlPacket::None => {}
                ControlPacket::Eof if state != HardenedProtocolState::Running => {
                    bail!("hardened discovery control closed before GO")
                }
                ControlPacket::Eof => control_eof = true,
                ControlPacket::Packet(packet) => {
                    if prepared.take_lease_break().map_err(anyhow::Error::msg)? {
                        child.terminate_and_wait()?;
                        return Ok(HardenedPassOutcome::LeaseBroken);
                    }
                    match state {
                        HardenedProtocolState::Prepared if packet == b"PREPARED" => {
                            selection.revalidate()?;
                            let child_process = selection.open_hardened_child(pid)?;
                            let maps_file = child_process.maps()?;
                            if child_process.exe_key()? != loader {
                                bail!("hardened discovery child did not execute the pinned loader");
                            }
                            if child_process.fd_identities()? != expected_fds {
                                bail!("hardened discovery child inherited an unexpected fd target");
                            }
                            self_memory = Some(child_process.memory_identity()?);
                            prepared.revalidate()?;
                            prepared.revalidate_seed(module)?;
                            poll_timeout(deadline)?;
                            if prepared.take_lease_break().map_err(anyhow::Error::msg)? {
                                child.terminate_and_wait()?;
                                return Ok(HardenedPassOutcome::LeaseBroken);
                            }
                            poll_timeout(deadline)?;
                            send_control(&parent_control, b"DROP")?;
                            process = Some(child_process);
                            maps = Some(maps_file);
                            state = HardenedProtocolState::Ready;
                        }
                        HardenedProtocolState::Ready if packet == b"READY" => {
                            selection.revalidate()?;
                            let child_process = process.as_ref().ok_or_else(|| {
                                anyhow!("hardened child proc authority is missing")
                            })?;
                            let maps_file = maps.as_ref().ok_or_else(|| {
                                anyhow!("hardened child maps authority is missing")
                            })?;
                            let maps_bytes = bounded_read(
                                maps_file,
                                crate::verify::MAX_MANIFEST_BYTES,
                                "hardened child maps",
                            )?;
                            validate_hardened_executable_maps(&maps_bytes, &executable, provider)?;
                            let ready_fds = child_process.fd_identities()?;
                            let memory_identity = self_memory.ok_or_else(|| {
                                anyhow!("hardened child self-memory identity is missing")
                            })?;
                            let exact_self_memory_addition = ready_fds.len()
                                == expected_fds.len() + 1
                                && expected_fds
                                    .iter()
                                    .all(|(fd, identity)| ready_fds.get(fd) == Some(identity))
                                && ready_fds.iter().any(|(fd, identity)| {
                                    !expected_fds.contains_key(fd) && *identity == memory_identity
                                });
                            if child_process.exe_key()? != loader || !exact_self_memory_addition {
                                bail!("hardened discovery child authority changed before GO");
                            }
                            prepared.revalidate()?;
                            prepared.revalidate_seed(module)?;
                            poll_timeout(deadline)?;
                            if prepared.take_lease_break().map_err(anyhow::Error::msg)? {
                                child.terminate_and_wait()?;
                                return Ok(HardenedPassOutcome::LeaseBroken);
                            }
                            poll_timeout(deadline)?;
                            send_control(&parent_control, b"GO")?;
                            state = HardenedProtocolState::Running;
                        }
                        _ => bail!("unexpected hardened discovery control packet {packet:?}"),
                    }
                }
            }
        }
    }
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
    use std::ffi::OsStr;
    use std::os::unix::fs::PermissionsExt as _;

    const HAPPY_PROTOCOL: &str = r#"
    if (send(control, "PREPARED", 8, 0) != 8) return 91;
    if (!expect(control, "DROP")) return 92;
    if (send(control, "READY", 5, 0) != 5) return 93;
    if (!expect(control, "GO")) return 94;
    int marker = open("@MARKER@", O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (marker < 0 || close(marker) != 0) return 95;
    if (dprintf(1, "{\"schema\":\"p11scope-manifest/4\",\"module_path\":\"@MODULE@\",\"objects\":[],\"provenance_objects\":[],\"interface_list\":{\"status\":\"absent\"},\"surfaces\":[],\"vendor_interfaces\":[],\"alias_groups\":[]}") < 0) return 96;
    return 0;
"#;

    fn hardened_protocol_root() -> (
        tempfile::TempDir,
        PathBuf,
        PathBuf,
        PathBuf,
        PathBuf,
        PathBuf,
    ) {
        hardened_protocol_root_with(HAPPY_PROTOCOL)
    }

    fn hardened_protocol_root_with(
        flow: &str,
    ) -> (
        tempfile::TempDir,
        PathBuf,
        PathBuf,
        PathBuf,
        PathBuf,
        PathBuf,
    ) {
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
        let marker = root.path().join("provider-loaded");
        let checkpoint = root.path().join("checkpoint");
        let mutated = root.path().join("mutation-done");
        let pid_file = root.path().join("oracle.pid");
        let source = root.path().join("opt/p11scope-discover.c");
        let program = r#"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static int self_memory = -1;

static __attribute__((unused)) int expect(int fd, const char *wanted) {
    char bytes[32];
    ssize_t n = recv(fd, bytes, sizeof(bytes), MSG_TRUNC);
    int matched = n == (ssize_t)strlen(wanted) && !memcmp(bytes, wanted, (size_t)n);
    if (matched && !strcmp(wanted, "DROP") && self_memory == -1) {
        self_memory = open("/proc/self/mem", O_RDONLY | O_CLOEXEC);
        if (self_memory == -1) return 0;
    }
    return matched;
}

int main(int argc, char **argv) {
    if (argc != 5) return 90;
    int control = atoi(argv[4]);
    FILE *pid_file = fopen("@PID_FILE@", "w");
    if (!pid_file || fprintf(pid_file, "%ld\n", (long)getpid()) < 0 || fclose(pid_file) != 0) return 89;
@FLOW@
}
"#
        .replace("@FLOW@", flow)
        .replace("@MARKER@", marker.to_str().unwrap())
        .replace("@CHECKPOINT@", checkpoint.to_str().unwrap())
        .replace("@MUTATED@", mutated.to_str().unwrap())
        .replace("@MODULE@", module.to_str().unwrap())
        .replace(
            "@REPLACEMENT@",
            root.path().join("opt/replacement.so").to_str().unwrap(),
        )
        .replace("@PID_FILE@", pid_file.to_str().unwrap());
        std::fs::write(&source, program).unwrap();
        let compiled = Command::new("gcc")
            .args(["-O2", "-Wall", "-Werror", "-o"])
            .arg(&helper)
            .arg(&source)
            .output()
            .unwrap();
        assert!(
            compiled.status.success(),
            "{}",
            String::from_utf8_lossy(&compiled.stderr)
        );
        std::fs::copy("/bin/false", &module).unwrap();
        std::fs::copy("/bin/true", root.path().join("opt/replacement.so")).unwrap();
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
        (root, helper, module, interpreter, marker, pid_file)
    }

    fn thread_cpu_time() -> Duration {
        let mut time = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        assert_eq!(
            unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut time) },
            0
        );
        Duration::new(time.tv_sec as u64, time.tv_nsec as u32)
    }

    fn assert_pid_esrch(pid: libc::pid_t) {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if unsafe { libc::kill(pid, 0) } == -1
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            {
                return;
            }
            assert!(Instant::now() < deadline, "process {pid} survived teardown");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn assert_leader_reaped(pid: libc::pid_t) {
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
        assert_pid_esrch(pid);
    }

    fn restore_private_aliases(prepared: &crate::oracle::PreparedGlibc<'_>) {
        let directory = prepared.private_directory_fd();
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(directory, &mut stat) }, 0);
        let mode = stat.st_mode & 0o777;
        assert_eq!(unsafe { libc::fchmod(directory, 0o700) }, 0);
        let aliases = prepared
            .alias_links()
            .map(|(name, target)| (name.to_owned(), target.to_owned()))
            .collect::<Vec<_>>();
        for (name, target) in aliases {
            let name = CString::new(name.as_bytes()).unwrap();
            let target = CString::new(target.as_bytes()).unwrap();
            unsafe {
                libc::unlinkat(directory, name.as_ptr(), 0);
            }
            assert_eq!(
                unsafe { libc::symlinkat(target.as_ptr(), directory, name.as_ptr()) },
                0
            );
        }
        assert_eq!(unsafe { libc::fchmod(directory, mode) }, 0);
    }

    fn spawn_alias_mutator(
        prepared: &crate::oracle::PreparedGlibc<'_>,
        checkpoint: &Path,
        mutated: &Path,
    ) -> libc::pid_t {
        let directory = prepared.private_directory_fd();
        let (name, _target) = prepared
            .alias_links()
            .find(|(name, _)| *name == OsStr::new("libc.so.6"))
            .unwrap();
        let name = CString::new(name.as_bytes()).unwrap();
        let replacement = c"/proc/self/fd/0";
        let checkpoint = CString::new(checkpoint.as_os_str().as_bytes()).unwrap();
        let mutated = CString::new(mutated.as_os_str().as_bytes()).unwrap();
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(directory, &mut stat) }, 0);
        let mode = stat.st_mode & 0o777;
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            for _ in 0..3000 {
                let checkpoint_fd =
                    unsafe { libc::open(checkpoint.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
                if checkpoint_fd >= 0 {
                    unsafe { libc::close(checkpoint_fd) };
                    break;
                }
                unsafe { libc::usleep(1000) };
            }
            let failed = unsafe {
                libc::fchmod(directory, 0o700) == -1
                    || libc::unlinkat(directory, name.as_ptr(), 0) == -1
                    || libc::symlinkat(replacement.as_ptr(), directory, name.as_ptr()) == -1
                    || libc::fchmod(directory, mode) == -1
            };
            if failed {
                unsafe { libc::_exit(20) };
            }
            let done = unsafe {
                libc::open(
                    mutated.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if done < 0 {
                unsafe { libc::_exit(21) };
            }
            unsafe {
                libc::close(done);
                libc::_exit(0);
            }
        }
        pid
    }

    fn hardened_test_selection() -> (Child, crate::oracle::OracleSelection) {
        let mut command = Command::new("/bin/sleep");
        command.arg("30");
        unsafe {
            command.pre_exec(|| {
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        let selection =
            crate::oracle::OracleSelection::hardened_for_pid_for_test(child.id()).unwrap();
        (child, selection)
    }

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
    fn hardened_executable_maps_require_the_exact_pre_authorized_set() {
        let helper = MappingFileKey {
            device_major: 8,
            device_minor: 1,
            inode: 11,
        };
        let loader = MappingFileKey {
            device_major: 8,
            device_minor: 1,
            inode: 12,
        };
        let provider = MappingFileKey {
            device_major: 8,
            device_minor: 1,
            inode: 13,
        };
        let expected = BTreeSet::from([helper, loader]);
        let exact = b"1000-2000 r-xp 00000000 08:01 11 /helper\n2000-3000 r-xp 00000000 08:01 12 /loader\n3000-4000 rw-p 00000000 00:00 0 [heap]\n";
        validate_hardened_executable_maps(exact, &expected, provider).unwrap();
        let repeated_authorized_inode = b"1000-2000 r-xp 00000000 08:01 11 /helper\n2000-3000 r-xp 00001000 08:01 11 /helper\n3000-4000 r-xp 00000000 08:01 12 /loader\n";
        validate_hardened_executable_maps(repeated_authorized_inode, &expected, provider).unwrap();

        for refused in [
            b"1000-2000 r-xp 00000000 08:01 11 /helper\n".as_slice(),
            b"1000-2000 r-xp 00000000 08:01 11 /helper\n2000-3000 r-xp 00000000 08:01 12 /loader\n3000-4000 r-xp 00000000 08:01 14 /extra\n",
            b"1000-2000 r-xp 00000000 08:01 11 /helper\n2000-3000 r-xp 00000000 08:01 12 /loader\n3000-4000 r-xp 00000000 08:01 13 /provider\n",
            b"not a maps line\n",
        ] {
            assert!(
                validate_hardened_executable_maps(refused, &expected, provider).is_err(),
                "accepted {refused:?}"
            );
        }
    }

    #[test]
    fn supervised_hardened_pass_completes_only_after_both_barriers() {
        let (root, _helper, module, _loader, marker, _pid_file) = hardened_protocol_root();
        let mut leases = ClosureLeases::new(&module).unwrap();
        let mut prepared = crate::oracle::prepare_glibc_test_root(
            root.path(),
            Path::new("/opt/p11scope-discover"),
            unsafe { libc::geteuid() },
            &mut leases,
        )
        .unwrap();
        let (mut target, selection) = hardened_test_selection();

        let outcome =
            run_hardened_pass(&selection, &prepared, &module, Duration::from_secs(5)).unwrap();
        let HardenedPassOutcome::Complete(manifest) = outcome else {
            panic!("lease unexpectedly broke");
        };
        assert_eq!(manifest.schema, SCHEMA);
        assert_eq!(manifest.module_path, module.to_str().unwrap());
        assert!(marker.exists());

        target.kill().unwrap();
        target.wait().unwrap();
        drop(selection);
        prepared.cleanup().unwrap();
    }

    #[test]
    fn supervised_hardened_pass_allows_the_post_drop_self_memory_fd() {
        let flow = r#"
            if (send(control, "PREPARED", 8, 0) != 8) return 2;
            if (!expect(control, "DROP")) return 3;
            if (send(control, "READY", 5, 0) != 5) return 4;
            if (!expect(control, "GO")) return 5;
            if (dprintf(1, "{\"schema\":\"p11scope-manifest/4\",\"module_path\":\"@MODULE@\",\"objects\":[],\"provenance_objects\":[],\"interface_list\":{\"status\":\"absent\"},\"surfaces\":[],\"vendor_interfaces\":[],\"alias_groups\":[]}") < 0) return 6;
            return 0;
        "#;
        let (root, _helper, module, _loader, _marker, _pid_file) =
            hardened_protocol_root_with(flow);
        let mut leases = ClosureLeases::new(&module).unwrap();
        let mut prepared = crate::oracle::prepare_glibc_test_root(
            root.path(),
            Path::new("/opt/p11scope-discover"),
            unsafe { libc::geteuid() },
            &mut leases,
        )
        .unwrap();
        let (mut target, selection) = hardened_test_selection();

        let outcome =
            run_hardened_pass(&selection, &prepared, &module, Duration::from_secs(5)).unwrap();
        assert!(matches!(outcome, HardenedPassOutcome::Complete(_)));

        target.kill().unwrap();
        target.wait().unwrap();
        drop(selection);
        prepared.cleanup().unwrap();
    }

    #[test]
    fn supervised_hardened_pass_refuses_an_extra_ready_fd() {
        let flow = r#"
            if (send(control, "PREPARED", 8, 0) != 8) return 2;
            if (!expect(control, "DROP")) return 3;
            int unexpected = open("/dev/null", O_RDONLY | O_CLOEXEC);
            if (unexpected < 0) return 4;
            if (send(control, "READY", 5, 0) != 5) return 5;
            pause();
            return 0;
        "#;
        let (root, _helper, module, _loader, _marker, pid_file) = hardened_protocol_root_with(flow);
        let mut leases = ClosureLeases::new(&module).unwrap();
        let mut prepared = crate::oracle::prepare_glibc_test_root(
            root.path(),
            Path::new("/opt/p11scope-discover"),
            unsafe { libc::geteuid() },
            &mut leases,
        )
        .unwrap();
        let (mut target, selection) = hardened_test_selection();

        let error =
            run_hardened_pass(&selection, &prepared, &module, Duration::from_secs(5)).unwrap_err();
        assert!(
            error.to_string().contains("authority changed before GO"),
            "{error:#}"
        );
        let pid = std::fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_leader_reaped(pid);

        target.kill().unwrap();
        target.wait().unwrap();
        drop(selection);
        prepared.cleanup().unwrap();
    }

    #[test]
    fn supervised_hardened_pass_rejects_invalid_or_abandoned_control_records() {
        let cases = [
            (
                r#"send(control, "WRONG", 5, 0); pause(); return 0;"#,
                "unexpected hardened discovery control packet",
                false,
            ),
            (
                r#"char packet[64] = {0}; send(control, packet, sizeof(packet), 0); pause(); return 0;"#,
                "exceeds 32 bytes",
                false,
            ),
            (
                r#"send(control, "PREP", 4, 0); pause(); return 0;"#,
                "unexpected hardened discovery control packet",
                false,
            ),
            (
                r#"send(control, "PREPARED", 8, 0); send(control, "PREPARED", 8, 0); pause(); return 0;"#,
                "unexpected hardened discovery control packet",
                false,
            ),
            (
                r#"shutdown(control, SHUT_WR); pause(); return 0;"#,
                "control closed before GO",
                false,
            ),
            (
                r#"
                send(control, "PREPARED", 8, 0); if (!expect(control, "DROP")) return 2;
                int checkpoint = open("@CHECKPOINT@", O_WRONLY | O_CREAT | O_EXCL, 0600);
                if (checkpoint < 0 || close(checkpoint) != 0) return 3;
                if (shutdown(control, SHUT_WR) != 0) return 4;
                pause(); return 0;
                "#,
                "control closed before GO",
                true,
            ),
            (
                r#"send(control, "PREPARED", 8, 0); if (!expect(control, "DROP")) return 2; send(control, "READY", 5, 0); if (!expect(control, "GO")) return 3; send(control, "EXTRA", 5, 0); dprintf(1, "{\"schema\":\"p11scope-manifest/4\",\"module_path\":\"@MODULE@\",\"objects\":[],\"provenance_objects\":[],\"interface_list\":{\"status\":\"absent\"},\"surfaces\":[],\"vendor_interfaces\":[],\"alias_groups\":[]}"); pause(); return 0;"#,
                "unexpected hardened discovery control packet",
                false,
            ),
        ];
        for (flow, expected_error, checkpoint_expected) in cases {
            let (root, _helper, module, _loader, marker, pid_file) =
                hardened_protocol_root_with(flow);
            let checkpoint = root.path().join("checkpoint");
            let mut leases = ClosureLeases::new(&module).unwrap();
            let mut prepared = crate::oracle::prepare_glibc_test_root(
                root.path(),
                Path::new("/opt/p11scope-discover"),
                unsafe { libc::geteuid() },
                &mut leases,
            )
            .unwrap();
            let (mut target, selection) = hardened_test_selection();

            let error = run_hardened_pass(&selection, &prepared, &module, Duration::from_secs(2))
                .unwrap_err();
            assert!(
                error.to_string().contains(expected_error),
                "{flow}: {error:#}"
            );
            assert!(!marker.exists(), "provider marker exists for {flow}");
            assert_eq!(
                checkpoint.exists(),
                checkpoint_expected,
                "wrong DROP checkpoint state for {flow}"
            );
            let pid: i32 = std::fs::read_to_string(&pid_file)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            assert_leader_reaped(pid);
            prepared.cleanup().unwrap();
            target.kill().unwrap();
            target.wait().unwrap();
        }
    }

    #[test]
    fn supervised_hardened_pass_uses_one_deadline_and_kills_stdout_leaks() {
        let cases = [
            (
                "(void)control; sleep(30); return 0;",
                Duration::from_millis(100),
                1,
            ),
            (
                r#"
                usleep(70000);
                if (send(control, "PREPARED", 8, 0) != 8) return 2;
                if (!expect(control, "DROP")) return 3;
                usleep(70000);
                if (send(control, "READY", 5, 0) != 5) return 4;
                if (!expect(control, "GO")) return 5;
                if (dprintf(1, "{\"schema\":\"p11scope-manifest/4\",\"module_path\":\"@MODULE@\",\"objects\":[],\"provenance_objects\":[],\"interface_list\":{\"status\":\"absent\"},\"surfaces\":[],\"vendor_interfaces\":[],\"alias_groups\":[]}") < 0) return 6;
                int sync_pipe[2]; if (pipe(sync_pipe) != 0) return 7;
                pid_t descendant = fork(); if (descendant < 0) return 8;
                if (descendant == 0) {
                    close(sync_pipe[0]); FILE *pid_file = fopen("@PID_FILE@", "a");
                    if (!pid_file || fprintf(pid_file, "%ld\n", (long)getpid()) < 0 || fclose(pid_file) != 0) _exit(9);
                    if (write(sync_pipe[1], "x", 1) != 1) _exit(10);
                    sleep(30); _exit(0);
                }
                close(sync_pipe[1]); char acknowledged;
                if (read(sync_pipe[0], &acknowledged, 1) != 1) return 11;
                close(sync_pipe[0]);
                return 0;
                "#,
                Duration::from_millis(190),
                2,
            ),
        ];
        for (flow, timeout, expected_pid_count) in cases {
            let (root, _helper, module, _loader, _marker, pid_file) =
                hardened_protocol_root_with(flow);
            let mut leases = ClosureLeases::new(&module).unwrap();
            let mut prepared = crate::oracle::prepare_glibc_test_root(
                root.path(),
                Path::new("/opt/p11scope-discover"),
                unsafe { libc::geteuid() },
                &mut leases,
            )
            .unwrap();
            let (mut target, selection) = hardened_test_selection();
            let started = Instant::now();

            let error = run_hardened_pass(&selection, &prepared, &module, timeout).unwrap_err();
            let elapsed = started.elapsed();
            assert!(error.to_string().contains("deadline"), "{error:#}");
            assert!(elapsed >= timeout, "deadline fired early: {elapsed:?}");
            assert!(
                elapsed < timeout + Duration::from_millis(250),
                "deadline was reset: {elapsed:?}"
            );
            let pids: Vec<libc::pid_t> = std::fs::read_to_string(&pid_file)
                .unwrap()
                .lines()
                .map(|line| line.parse().unwrap())
                .collect();
            assert_eq!(pids.len(), expected_pid_count);
            assert_leader_reaped(pids[0]);
            for descendant in &pids[1..] {
                assert_pid_esrch(*descendant);
            }
            prepared.cleanup().unwrap();
            target.kill().unwrap();
            target.wait().unwrap();
        }
    }

    #[test]
    fn supervised_hardened_pass_blocks_after_leader_exit_until_stdout_deadline() {
        let flow = r#"
            if (send(control, "PREPARED", 8, 0) != 8) return 2;
            if (!expect(control, "DROP")) return 3;
            if (send(control, "READY", 5, 0) != 5) return 4;
            if (!expect(control, "GO")) return 5;
            if (dprintf(1, "{\"schema\":\"p11scope-manifest/4\",\"module_path\":\"@MODULE@\",\"objects\":[],\"provenance_objects\":[],\"interface_list\":{\"status\":\"absent\"},\"surfaces\":[],\"vendor_interfaces\":[],\"alias_groups\":[]}") < 0) return 6;
            int sync_pipe[2]; if (pipe(sync_pipe) != 0) return 7;
            pid_t descendant = fork(); if (descendant < 0) return 8;
            if (descendant == 0) {
                close(sync_pipe[0]);
                FILE *pid_file = fopen("@PID_FILE@", "a");
                if (!pid_file || fprintf(pid_file, "%ld\n", (long)getpid()) < 0 || fclose(pid_file) != 0) _exit(9);
                if (write(sync_pipe[1], "x", 1) != 1) _exit(10);
                sleep(30); _exit(0);
            }
            close(sync_pipe[1]); char acknowledged;
            if (read(sync_pipe[0], &acknowledged, 1) != 1) return 11;
            close(sync_pipe[0]); return 0;
        "#;
        let timeout = Duration::from_millis(220);
        let (root, _helper, module, _loader, _marker, pid_file) = hardened_protocol_root_with(flow);
        let mut leases = ClosureLeases::new(&module).unwrap();
        let mut prepared = crate::oracle::prepare_glibc_test_root(
            root.path(),
            Path::new("/opt/p11scope-discover"),
            unsafe { libc::geteuid() },
            &mut leases,
        )
        .unwrap();
        let (mut target, selection) = hardened_test_selection();
        let wall_started = Instant::now();
        let cpu_started = thread_cpu_time();

        let error = match run_hardened_pass(&selection, &prepared, &module, timeout) {
            Err(error) => error,
            Ok(_) => panic!("accepted incomplete stdout after its deadline"),
        };
        let cpu_elapsed = thread_cpu_time() - cpu_started;
        let wall_elapsed = wall_started.elapsed();

        assert!(error.to_string().contains("deadline"), "{error:#}");
        assert!(
            wall_elapsed >= timeout,
            "deadline fired early: {wall_elapsed:?}"
        );
        assert!(
            cpu_elapsed < Duration::from_millis(60),
            "pidfd readiness busy-spun for {cpu_elapsed:?} CPU over {wall_elapsed:?} wall"
        );
        let pids: Vec<libc::pid_t> = std::fs::read_to_string(&pid_file)
            .unwrap()
            .lines()
            .map(|line| line.parse().unwrap())
            .collect();
        assert_eq!(
            pids.len(),
            2,
            "leader and descendant were not both recorded"
        );
        assert_leader_reaped(pids[0]);
        assert_pid_esrch(pids[1]);
        prepared.cleanup().unwrap();
        target.kill().unwrap();
        target.wait().unwrap();
    }

    #[test]
    fn supervised_hardened_pass_refuses_result_completed_after_deadline() {
        let flow = r#"
            if (send(control, "PREPARED", 8, 0) != 8) return 2;
            if (!expect(control, "DROP")) return 3;
            if (send(control, "READY", 5, 0) != 5) return 4;
            if (!expect(control, "GO")) return 5;
            struct timespec started, now;
            if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) return 6;
            if (dprintf(1, "{\"schema\":\"p11scope-manifest/4\",\"module_path\":\"") < 0) return 7;
            char escaped[6000];
            for (int i = 0; i < 1000; i++) memcpy(escaped + i * 6, "\\u0061", 6);
            for (int i = 0; i < 2500; i++) if (write(1, escaped, sizeof(escaped)) != sizeof(escaped)) return 8;
            if (dprintf(1, "\",\"objects\":[],\"provenance_objects\":[],\"interface_list\":{\"status\":\"absent\"},\"surfaces\":[],\"vendor_interfaces\":[],\"alias_groups\":[]}") < 0) return 9;
            do {
                if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 10;
                long elapsed_ms = (now.tv_sec - started.tv_sec) * 1000 + (now.tv_nsec - started.tv_nsec) / 1000000;
                if (elapsed_ms >= 200) break;
                usleep(1000);
            } while (1);
            return 0;
        "#;
        let timeout = Duration::from_millis(230);
        let (root, _helper, module, _loader, _marker, _pid_file) =
            hardened_protocol_root_with(flow);
        let mut leases = ClosureLeases::new(&module).unwrap();
        let mut prepared = crate::oracle::prepare_glibc_test_root(
            root.path(),
            Path::new("/opt/p11scope-discover"),
            unsafe { libc::geteuid() },
            &mut leases,
        )
        .unwrap();
        let (mut target, selection) = hardened_test_selection();
        let started = Instant::now();

        let error = match run_hardened_pass(&selection, &prepared, &module, timeout) {
            Err(error) => error,
            Ok(_) => panic!("accepted hardened discovery result after its deadline"),
        };

        assert!(error.to_string().contains("deadline"), "{error:#}");
        assert!(started.elapsed() >= timeout);
        prepared.cleanup().unwrap();
        target.kill().unwrap();
        target.wait().unwrap();
    }

    #[test]
    fn supervised_hardened_pass_refuses_authority_output_and_exit_mutations() {
        let cases = [
            (
                r#"
                send(control, "PREPARED", 8, 0); if (!expect(control, "DROP")) return 2;
                int checkpoint = open("@CHECKPOINT@", O_WRONLY | O_CREAT | O_EXCL, 0600);
                int fd = open("/bin/false", O_RDONLY);
                int helper_fd = atoi(strrchr(argv[0], '/') + 1);
                if (checkpoint < 0 || close(checkpoint) != 0 || fd < 0 || dup2(fd, helper_fd) < 0) return 3;
                close(fd); send(control, "READY", 5, 0); pause(); return 0;
                "#,
                "authority changed before GO",
                false,
            ),
            (
                r#"
                send(control, "PREPARED", 8, 0); if (!expect(control, "DROP")) return 2;
                send(control, "READY", 5, 0); if (!expect(control, "GO")) return 3;
                int checkpoint = open("@CHECKPOINT@", O_WRONLY | O_CREAT | O_EXCL, 0600);
                if (checkpoint < 0 || close(checkpoint) != 0) return 4;
                for (int i = 0; i < 3000 && access("@MUTATED@", F_OK) != 0; i++) usleep(1000);
                if (access("@MUTATED@", F_OK) != 0) return 5;
                dprintf(1, "{\"schema\":\"p11scope-manifest/4\",\"module_path\":\"@MODULE@\",\"objects\":[],\"provenance_objects\":[],\"interface_list\":{\"status\":\"absent\"},\"surfaces\":[],\"vendor_interfaces\":[],\"alias_groups\":[]}"); return 0;
                "#,
                "was retargeted",
                true,
            ),
            (
                r#"
                send(control, "PREPARED", 8, 0); if (!expect(control, "DROP")) return 2;
                send(control, "READY", 5, 0); if (!expect(control, "GO")) return 3;
                int checkpoint = open("@CHECKPOINT@", O_WRONLY | O_CREAT | O_EXCL, 0600);
                if (checkpoint < 0 || close(checkpoint) != 0 || rename("@REPLACEMENT@", "@MODULE@") != 0) return 4;
                dprintf(1, "{\"schema\":\"p11scope-manifest/4\",\"module_path\":\"@MODULE@\",\"objects\":[],\"provenance_objects\":[],\"interface_list\":{\"status\":\"absent\"},\"surfaces\":[],\"vendor_interfaces\":[],\"alias_groups\":[]}"); return 0;
                "#,
                "provenance module",
                false,
            ),
            (
                r#"
                send(control, "PREPARED", 8, 0); if (!expect(control, "DROP")) return 2;
                int checkpoint = open("@CHECKPOINT@", O_WRONLY | O_CREAT | O_EXCL, 0600);
                int fd = open("/bin/true", O_RDONLY); struct stat st; if (checkpoint < 0 || close(checkpoint) != 0 || fd < 0 || fstat(fd, &st) != 0) return 3;
                if (mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0) == MAP_FAILED) return 4;
                close(fd); send(control, "READY", 5, 0); pause(); return 0;
                "#,
                "executable mappings differ",
                false,
            ),
            (
                r#"
                send(control, "PREPARED", 8, 0); if (!expect(control, "DROP")) return 2;
                int checkpoint = open("@CHECKPOINT@", O_WRONLY | O_CREAT | O_EXCL, 0600);
                int fd = open("@MODULE@", O_RDONLY); struct stat st; if (checkpoint < 0 || close(checkpoint) != 0 || fd < 0 || fstat(fd, &st) != 0) return 3;
                if (mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0) == MAP_FAILED) return 4;
                close(fd); send(control, "READY", 5, 0); pause(); return 0;
                "#,
                "provider was executable before hardened discovery GO",
                false,
            ),
            (
                r#"
                send(control, "PREPARED", 8, 0); if (!expect(control, "DROP")) return 2;
                send(control, "READY", 5, 0); if (!expect(control, "GO")) return 3;
                int checkpoint = open("@CHECKPOINT@", O_WRONLY | O_CREAT | O_EXCL, 0600);
                if (checkpoint < 0 || close(checkpoint) != 0) return 4;
                char bytes[8192] = {0}; for (int i = 0; i < 2049; i++) if (write(1, bytes, sizeof(bytes)) != sizeof(bytes)) return 5;
                return 0;
                "#,
                "byte limit",
                false,
            ),
            (
                r#"
                send(control, "PREPARED", 8, 0); if (!expect(control, "DROP")) return 2;
                send(control, "READY", 5, 0); if (!expect(control, "GO")) return 3;
                int checkpoint = open("@CHECKPOINT@", O_WRONLY | O_CREAT | O_EXCL, 0600);
                if (checkpoint < 0 || close(checkpoint) != 0) return 4;
                return 7;
                "#,
                "exited with 7",
                false,
            ),
        ];
        for (flow, expected_error, restore_alias) in cases {
            let (root, _helper, module, _loader, marker, pid_file) =
                hardened_protocol_root_with(flow);
            let checkpoint = root.path().join("checkpoint");
            let mut leases = ClosureLeases::new(&module).unwrap();
            let mut prepared = crate::oracle::prepare_glibc_test_root(
                root.path(),
                Path::new("/opt/p11scope-discover"),
                unsafe { libc::geteuid() },
                &mut leases,
            )
            .unwrap();
            let (mut target, selection) = hardened_test_selection();
            let alias_mutator = restore_alias.then(|| {
                spawn_alias_mutator(&prepared, &checkpoint, &root.path().join("mutation-done"))
            });

            let error = run_hardened_pass(&selection, &prepared, &module, Duration::from_secs(3))
                .unwrap_err();
            assert!(
                error.to_string().contains(expected_error),
                "{flow}: {error:#}"
            );
            assert!(!marker.exists());
            assert!(checkpoint.exists(), "phase checkpoint missing for {flow}");
            let pid: i32 = std::fs::read_to_string(&pid_file)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            assert_leader_reaped(pid);
            if let Some(alias_mutator) = alias_mutator {
                let mut status = 0;
                assert_eq!(
                    unsafe { libc::waitpid(alias_mutator, &mut status, 0) },
                    alias_mutator
                );
                assert!(libc::WIFEXITED(status));
                assert_eq!(libc::WEXITSTATUS(status), 0);
                restore_private_aliases(&prepared);
            }
            prepared.cleanup().unwrap();
            target.kill().unwrap();
            target.wait().unwrap();
        }
    }

    #[test]
    fn supervised_hardened_pass_reports_lease_break_only_after_reaping() {
        let flow = format!("usleep(200000); {HAPPY_PROTOCOL}");
        let (root, _helper, module, _loader, marker, pid_file) = hardened_protocol_root_with(&flow);
        let mut leases = ClosureLeases::new(&module).unwrap();
        #[repr(C)]
        struct LeaseOwner {
            kind: libc::c_int,
            pid: libc::pid_t,
        }
        const F_OWNER_TID: libc::c_int = 0;
        const F_SETOWN_EX: libc::c_int = 15;
        let owner = LeaseOwner {
            kind: F_OWNER_TID,
            pid: unsafe { libc::syscall(libc::SYS_gettid) as libc::pid_t },
        };
        assert_eq!(
            unsafe {
                libc::fcntl(
                    leases.objects.get(&leases.seed).unwrap().file.as_raw_fd(),
                    F_SETOWN_EX,
                    &owner,
                )
            },
            0
        );
        let mut prepared = crate::oracle::prepare_glibc_test_root(
            root.path(),
            Path::new("/opt/p11scope-discover"),
            unsafe { libc::geteuid() },
            &mut leases,
        )
        .unwrap();
        let (mut target, selection) = hardened_test_selection();
        let writer_module = module.clone();
        let writer_pid_file = pid_file.clone();
        let writer = std::thread::spawn(move || {
            while !writer_pid_file.exists() {
                std::thread::sleep(Duration::from_millis(1));
            }
            OpenOptions::new().write(true).open(writer_module).unwrap();
        });

        let outcome =
            run_hardened_pass(&selection, &prepared, &module, Duration::from_secs(3)).unwrap();
        assert!(matches!(outcome, HardenedPassOutcome::LeaseBroken));
        assert!(!marker.exists());
        let pid: i32 = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1, "child {pid} survived");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
        prepared.cleanup().unwrap();
        drop(prepared);
        drop(leases);
        writer.join().unwrap();
        target.kill().unwrap();
        target.wait().unwrap();
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
    fn hardened_stabilization_preleases_exact_inodes_and_converges() {
        let (root, helper, module, interpreter, _marker, _pid_file) = hardened_protocol_root();
        let libc = root.path().join("usr/lib/x86_64-linux-gnu/libc.so.6");
        let dependency = root.path().join("opt/dependency.so");
        std::fs::copy("/bin/true", &dependency).unwrap();
        let manifests = [
            closure_manifest(&module, &[&module, &helper, &interpreter, &libc]),
            closure_manifest(
                &module,
                &[&module, &helper, &interpreter, &libc, &dependency],
            ),
            closure_manifest(
                &module,
                &[&module, &helper, &interpreter, &libc, &dependency],
            ),
        ];
        let (mut target, selection) = hardened_test_selection();
        let mut leases = ClosureLeases::new(&module).unwrap();
        let mut prepared = crate::oracle::prepare_glibc_test_root(
            root.path(),
            Path::new("/opt/p11scope-discover"),
            unsafe { libc::geteuid() },
            &mut leases,
        )
        .unwrap();
        let preleased_count = prepared.stabilization_keys().unwrap().len();
        let mut passes = 0;
        let mut private_directory = None;

        let outcome = stabilize_hardened(&module, &selection, &mut prepared, |prepared| {
            let fd = prepared.private_directory_fd();
            assert_eq!(*private_directory.get_or_insert(fd), fd);
            let manifest = manifests[passes].clone();
            passes += 1;
            Ok(HardenedPassOutcome::Complete(manifest))
        })
        .unwrap();

        let HardenedPassOutcome::Complete(manifest) = outcome else {
            panic!("lease unexpectedly broke");
        };
        assert_eq!(passes, 3);
        assert_eq!(manifest, manifests[2]);
        prepared.cleanup().unwrap();
        drop(prepared);
        assert_eq!(leases.influences.len(), preleased_count - 1);
        assert_eq!(leases.objects.len(), 2);
        target.kill().unwrap();
        target.wait().unwrap();

        let (root, helper, module, interpreter, _marker, _pid_file) = hardened_protocol_root();
        let libc = root.path().join("usr/lib/x86_64-linux-gnu/libc.so.6");
        let first = root.path().join("opt/first.so");
        let replacement = root.path().join("opt/replacement-dependency.so");
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
        let manifests = [
            closure_manifest(&module, &[&module, &helper, &interpreter, &libc, &first]),
            closure_manifest(
                &module,
                &[&module, &helper, &interpreter, &libc, &replacement],
            ),
            closure_manifest(
                &module,
                &[&module, &helper, &interpreter, &libc, &replacement],
            ),
        ];
        let (mut target, selection) = hardened_test_selection();
        let mut leases = ClosureLeases::new(&module).unwrap();
        let mut prepared = crate::oracle::prepare_glibc_test_root(
            root.path(),
            Path::new("/opt/p11scope-discover"),
            unsafe { libc::geteuid() },
            &mut leases,
        )
        .unwrap();
        let mut passes = 0;

        let outcome = stabilize_hardened(&module, &selection, &mut prepared, |_| {
            let manifest = manifests[passes].clone();
            passes += 1;
            Ok(HardenedPassOutcome::Complete(manifest))
        })
        .unwrap();

        let HardenedPassOutcome::Complete(manifest) = outcome else {
            panic!("lease unexpectedly broke");
        };
        assert_eq!(passes, 3);
        assert_eq!(manifest, manifests[2]);
        prepared.cleanup().unwrap();
        drop(prepared);
        target.kill().unwrap();
        target.wait().unwrap();
    }

    #[test]
    fn hardened_stabilization_refuses_authority_change_and_inode_churn() {
        let (root, helper, module, interpreter, _marker, _pid_file) = hardened_protocol_root();
        let libc = root.path().join("usr/lib/x86_64-linux-gnu/libc.so.6");
        let replacement = root.path().join("opt/replacement.so");
        let manifest = closure_manifest(&module, &[&module, &helper, &interpreter, &libc]);
        let (mut target, selection) = hardened_test_selection();
        let mut leases = ClosureLeases::new(&module).unwrap();
        let mut prepared = crate::oracle::prepare_glibc_test_root(
            root.path(),
            Path::new("/opt/p11scope-discover"),
            unsafe { libc::geteuid() },
            &mut leases,
        )
        .unwrap();
        let mut passes = 0;

        let result = stabilize_hardened(&module, &selection, &mut prepared, |_| {
            passes += 1;
            if passes == 1 {
                std::fs::rename(&replacement, &module).unwrap();
            }
            Ok(HardenedPassOutcome::Complete(manifest.clone()))
        });

        prepared.cleanup().unwrap();
        drop(prepared);
        target.kill().unwrap();
        target.wait().unwrap();
        let error = result.unwrap_err();
        assert_eq!(passes, 1);
        assert!(error.to_string().contains("was replaced"), "{error:#}");

        let (root, helper, module, interpreter, _marker, _pid_file) = hardened_protocol_root();
        let libc = root.path().join("usr/lib/x86_64-linux-gnu/libc.so.6");
        let manifest = closure_manifest(&module, &[&module, &helper, &interpreter, &libc]);
        let (mut target, selection) = hardened_test_selection();
        let mut leases = ClosureLeases::new(&module).unwrap();
        let mut prepared = crate::oracle::prepare_glibc_test_root(
            root.path(),
            Path::new("/opt/p11scope-discover"),
            unsafe { libc::geteuid() },
            &mut leases,
        )
        .unwrap();
        let mut passes = 0;

        let result = stabilize_hardened(&module, &selection, &mut prepared, |_| {
            passes += 1;
            if passes == 1 {
                target.kill().unwrap();
                target.wait().unwrap();
            }
            Ok(HardenedPassOutcome::Complete(manifest.clone()))
        });

        prepared.cleanup().unwrap();
        drop(prepared);
        let error = result.unwrap_err();
        assert_eq!(passes, 1);
        assert!(
            error.to_string().contains("exited while its authority"),
            "{error:#}"
        );

        let (root, helper, module, interpreter, _marker, _pid_file) = hardened_protocol_root();
        let libc = root.path().join("usr/lib/x86_64-linux-gnu/libc.so.6");
        let first = root.path().join("opt/first.so");
        let second = root.path().join("opt/second.so");
        std::fs::copy("/bin/false", &first).unwrap();
        std::fs::copy(&first, &second).unwrap();
        let manifests = [
            closure_manifest(&module, &[&module, &helper, &interpreter, &libc, &first]),
            closure_manifest(&module, &[&module, &helper, &interpreter, &libc, &second]),
        ];
        let (mut target, selection) = hardened_test_selection();
        let mut leases = ClosureLeases::new(&module).unwrap();
        let mut prepared = crate::oracle::prepare_glibc_test_root(
            root.path(),
            Path::new("/opt/p11scope-discover"),
            unsafe { libc::geteuid() },
            &mut leases,
        )
        .unwrap();
        let mut passes = 0;

        let result = stabilize_hardened(&module, &selection, &mut prepared, |_| {
            let manifest = manifests[passes % 2].clone();
            passes += 1;
            Ok(HardenedPassOutcome::Complete(manifest))
        });

        prepared.cleanup().unwrap();
        drop(prepared);
        target.kill().unwrap();
        target.wait().unwrap();
        let error = result.unwrap_err();
        assert_eq!(passes, MAX_STABILIZATION_PASSES);
        assert!(error.to_string().contains("did not stabilize"), "{error:#}");
    }

    #[test]
    fn hardened_stabilization_cleans_before_exit_78() {
        let (root, _helper, module, _interpreter, _marker, _pid_file) = hardened_protocol_root();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let mut leases = ClosureLeases::new(&module).unwrap();
            let prepared = crate::oracle::prepare_glibc_test_root(
                root.path(),
                Path::new("/opt/p11scope-discover"),
                unsafe { libc::geteuid() },
                &mut leases,
            )
            .unwrap();
            let _ = finalize_hardened_prepared(prepared, Ok(HardenedPassOutcome::LeaseBroken));
            unsafe { libc::_exit(99) };
        }

        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(
            libc::WEXITSTATUS(status),
            crate::verify::OBJECT_CHANGED_EXIT
        );
        assert_eq!(
            std::fs::read_dir(root.path().join("run/p11scope"))
                .unwrap()
                .count(),
            0
        );
    }

    #[test]
    fn hardened_production_finalization_returns_live_stable_discovery() {
        let (root, helper, module, interpreter, _marker, _pid_file) = hardened_protocol_root();
        let libc = root.path().join("usr/lib/x86_64-linux-gnu/libc.so.6");
        let manifest = closure_manifest(&module, &[&module, &helper, &interpreter, &libc]);
        let (mut target, selection) = hardened_test_selection();
        let mut leases = ClosureLeases::new(&module).unwrap();
        let mut prepared = crate::oracle::prepare_glibc_test_root(
            root.path(),
            Path::new("/opt/p11scope-discover"),
            unsafe { libc::geteuid() },
            &mut leases,
        )
        .unwrap();
        let mut passes = 0;
        let stabilization = stabilize_hardened(&module, &selection, &mut prepared, |_| {
            passes += 1;
            Ok(HardenedPassOutcome::Complete(manifest.clone()))
        });
        let finalized = finalize_hardened_prepared(prepared, stabilization).unwrap();

        let stable = finish_hardened(&module, leases, finalized).unwrap();

        assert_eq!(passes, 2);
        assert_eq!(stable.manifest(), &manifest);
        stable.ensure_stable().unwrap();
        assert_eq!(
            std::fs::read_dir(root.path().join("run/p11scope"))
                .unwrap()
                .count(),
            0
        );
        target.kill().unwrap();
        target.wait().unwrap();
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
#include <sys/prctl.h>
#include <unistd.h>

int main(int argc, char **argv, char **envp) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return 4;
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
        let mut child = prepared.spawn_helper(&module, child_control).unwrap();
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
                        child.terminate_and_wait().unwrap();
                        panic!("hardened helper did not reach its stop barrier");
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("reading hardened helper facts failed: {error}"),
            }
        }
        let stopped = loop {
            let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
            if status.lines().any(|line| line.starts_with("State:\tT")) {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(1));
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
        let selection = crate::oracle::OracleSelection::hardened_for_pid_for_test(pid).unwrap();
        let process = selection.open_hardened_child(pid).unwrap();
        assert_eq!(
            process.exe_key().unwrap(),
            mapping_file_key(&File::open(&interpreter).unwrap()).unwrap()
        );
        let actual_fds = process
            .fd_identities()
            .unwrap()
            .into_keys()
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
}
