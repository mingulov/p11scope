//! SPDX-License-Identifier: GPL-3.0-or-later
//! Task 3 Stage A: the Session side of the load-instance continuity witness.
//!
//! - Loads and attaches the three native fentry hooks (`uprobe_mmap`,
//!   `uprobe_munmap`, `copy_vma`) after the mandatory lifecycle links. Any
//!   load or attach failure leaves the capture running with instance routing
//!   **refused** and a named reason; it never degrades the proof. An LTO
//!   kernel — or one whose LTO status is unverifiable — is refused before
//!   any attach, since inlined hook-target copies escape fentry (B2).
//! - Keeps ordering I1 per pinned provider file: hooks attached, then the
//!   file's kernel key is *calibrated* (the observer maps one page of the
//!   pinned fd and the hook records the `vm_file->f_inode` identity it saw),
//!   then `WATCHED_FILES` is inserted, then `SLOT_FILE` for each endpoint,
//!   and only then the endpoint links. A refused calibration leaves the
//!   endpoint unmapped, so its calls stamp `NO_FILE` and never route.
//! - Exposes the bracketed readers the userspace router needs (process
//!   record through a pidfd, global/fault/sticky cells, image cookie) and the
//!   hook programs' run/miss statistics.

use super::{BPF_MAP_LOOKUP_ELEM, BpfMapElementAttr, bpf_map_element_syscall};
use crate::discovery::identity::{PinnedObjectId, PinnedObjects};
use crate::discovery::instances::MappedFileIdentity;
use crate::plan::Slot;
use anyhow::{Context as _, Result, anyhow, bail, ensure};
use aya::maps::{Array, HashMap, MapData};
use aya::programs::fentry::FEntryLinkId;
use aya::programs::fexit::FExitLinkId;
use aya::programs::{FEntry, FExit};
use aya::{Btf, Ebpf};
use p11scope_ebpf_common::{
    InstanceCalib, InstanceCounters, InstanceFileKey, InstanceRecord, instance,
};
use p11scope_manifest::maps::ObjectKey;
use std::collections::BTreeMap;
use std::fs::File;
use std::mem::size_of_val;
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd};
use std::path::{Path, PathBuf};

/// The native hook programs and their kernel attach targets. `copy_vma`'s
/// first argument is a pointer-to-pointer, which no kernel admits as fentry
/// context, so its hook is an fexit reading the returned new VMA (same file,
/// same mm; still under the mremap mmap write lock).
pub(crate) const INSTANCE_PROGRAMS: [(&str, &str); 3] = [
    ("p11_inst_vma_map", "uprobe_mmap"),
    ("p11_inst_vma_unmap", "uprobe_munmap"),
    ("p11_inst_vma_copy", "copy_vma"),
];

/// Hooks attached as fexit; every other instance hook is fentry.
const EXIT_PROGRAMS: [&str; 1] = ["p11_inst_vma_copy"];

#[derive(Debug)]
enum HookLink {
    Entry(FEntryLinkId),
    Exit(FExitLinkId),
}

/// One watched provider file.
#[derive(Clone, Debug)]
pub(crate) struct WatchedFile {
    pub(crate) file_slot: u32,
    /// The maps-visible keys this pinned object is known under; the scan
    /// selects the file's ranges in `/proc/PID/maps` by these.
    pub(crate) maps_keys: Vec<ObjectKey>,
    /// The file's map_files `stat()` identity, recorded at calibration; a
    /// scan keeps only ranges with exactly this identity.
    pub(crate) identity: MappedFileIdentity,
}

/// Hook statistics for one fentry program (`BPF_OBJ_GET_INFO_BY_FD`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct HookStats {
    pub(crate) run_time_ns: u64,
    pub(crate) run_cnt: u64,
    pub(crate) recursion_misses: u64,
}

#[derive(Debug, Default)]
pub(crate) struct InstanceTracking {
    /// `None` while active; the refusal reason otherwise.
    refused: Option<String>,
    links: Vec<(&'static str, HookLink)>,
    watched: BTreeMap<PinnedObjectId, Result<WatchedFile, String>>,
    keys: BTreeMap<InstanceFileKey, u32>,
    next_slot: u32,
}

/// Test-only Stage A measurement toggle (Task 1d): `P11SCOPE_T3A_DISABLE_HOOKS`
/// set to exactly `1` refuses the hooks with a named reason, so the ABBA
/// overhead gate (`scripts/bench-stagea-overhead.sh`) can compare with and
/// without the hooks on one binary. Anything else, including unset, attaches
/// as usual; default paths are behavior-identical.
const DISABLE_HOOKS_ENV: &str = "P11SCOPE_T3A_DISABLE_HOOKS";

/// Pure predicate over the toggle value: only exactly `1` disables.
fn hooks_disabled_by_env_value(value: Option<&std::ffi::OsStr>) -> bool {
    value.is_some_and(|value| value == "1")
}

fn hooks_disabled_by_env() -> bool {
    hooks_disabled_by_env_value(std::env::var_os(DISABLE_HOOKS_ENV).as_deref())
}

/// Pure LTO predicate over one kernel-config text (B2): any enabled
/// `CONFIG_LTO_*` selection other than `CONFIG_LTO_NONE` means an LTO
/// kernel, whose inlined hook-target copies escape fentry. Arch capability
/// lines (`CONFIG_ARCH_SUPPORTS_LTO_*`) and `# ... is not set` comments
/// never match; a config without LTO lines predates LTO and is LTO-off.
pub(crate) fn lto_enabled_in_config(config: &str) -> bool {
    config.lines().any(|line| {
        let line = line.trim();
        line.starts_with("CONFIG_LTO") && line != "CONFIG_LTO_NONE=y" && line.ends_with("=y")
    })
}

/// Kernel LTO preflight (B2): refuses the hooks on LTO kernels, and on
/// kernels whose LTO status is unverifiable (no readable config for the
/// RUNNING release), with a named reason each. Reads only the distro
/// `/boot/config-{release}`: `/proc/config.gz` needs a gzip decoder the
/// dependency closure does not have, and `/lib/modules` copies carry the
/// same container-mismatch hazard as `/boot` without adding authority.
/// Stage 5 per-cell preflight re-verifies LTO status on every matrix cell
/// (DR-T3A-2); relaxing the unverifiable arm needs an owner decision.
fn lto_refusal() -> Option<String> {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|release| release.trim().to_owned())
        .unwrap_or_default();
    if release.is_empty() {
        return Some(
            "instance continuity hooks refused: cannot read the running kernel release".to_string(),
        );
    }
    let path = format!("/boot/config-{release}");
    let config = match std::fs::read_to_string(&path) {
        Ok(config) => config,
        Err(error) => {
            return Some(format!(
                "instance continuity hooks refused: LTO status unverifiable (no readable kernel config: {path}: {error})"
            ));
        }
    };
    if lto_enabled_in_config(&config) {
        return Some(format!(
            "instance continuity hooks refused: LTO kernel ({path} enables CONFIG_LTO_*; inlined hook-target copies escape fentry)"
        ));
    }
    None
}

impl InstanceTracking {
    /// Number of owned hook links currently attached (0 when refused).
    /// The privileged link-inventory gates add this to `Session.links`
    /// when reconciling kernel-owned link IDs: continuity hooks are
    /// attached to the session's programs but retained here, not in
    /// `Session.links`.
    pub(crate) fn hook_link_count(&self) -> usize {
        self.links.len()
    }

    /// Loads and attaches the hooks. Never fails the session: a failure is
    /// returned as a refused tracker whose reason names the first error.
    /// Refusal order is measurement toggle, then policy (Task 1d: metrics
    /// never joins per-call records, so it never pays the hooks), then LTO.
    pub(crate) fn start(ebpf: &mut Ebpf, btf: &Btf, policy: super::CapturePolicy) -> Self {
        let mut tracking = Self::default();
        if hooks_disabled_by_env() {
            tracking.refused = Some(format!(
                "instance continuity hooks refused: disabled by {DISABLE_HOOKS_ENV}=1 (Stage A overhead measurement)"
            ));
            return tracking;
        }
        if !policy.wants_instance_hooks() {
            tracking.refused = Some(
                "instance continuity hooks refused: aggregate-only (metrics) sessions never join per-call records to load instances (Task 1d overhead gate)"
                    .to_string(),
            );
            return tracking;
        }
        if let Some(reason) = lto_refusal() {
            tracking.refused = Some(reason);
            return tracking;
        }
        if let Err(error) = tracking.attach_hooks(ebpf, btf) {
            tracking.refused = Some(format!("instance continuity hooks unavailable: {error:#}"));
            for (program, link) in std::mem::take(&mut tracking.links) {
                let Some(hook) = ebpf.program_mut(program) else {
                    continue;
                };
                match link {
                    HookLink::Entry(id) => {
                        if let Ok(hook) = <&mut FEntry>::try_from(hook) {
                            let _ = hook.detach(id);
                        }
                    }
                    HookLink::Exit(id) => {
                        if let Ok(hook) = <&mut FExit>::try_from(hook) {
                            let _ = hook.detach(id);
                        }
                    }
                }
            }
        }
        tracking
    }

    fn attach_hooks(&mut self, ebpf: &mut Ebpf, btf: &Btf) -> Result<()> {
        for (program, target) in INSTANCE_PROGRAMS {
            let hook = ebpf
                .program_mut(program)
                .with_context(|| format!("program {program} missing from object"))?;
            if EXIT_PROGRAMS.contains(&program) {
                <&mut FExit>::try_from(hook)?
                    .load(target, btf)
                    .with_context(|| format!("loading fexit {program} on {target}"))?;
            } else {
                <&mut FEntry>::try_from(hook)?
                    .load(target, btf)
                    .with_context(|| format!("loading fentry {program} on {target}"))?;
            }
        }
        for (program, target) in INSTANCE_PROGRAMS {
            let hook = ebpf
                .program_mut(program)
                .with_context(|| format!("program {program} missing from object"))?;
            let link = if EXIT_PROGRAMS.contains(&program) {
                HookLink::Exit(
                    <&mut FExit>::try_from(hook)?
                        .attach()
                        .with_context(|| format!("attaching fexit {program} on {target}"))?,
                )
            } else {
                HookLink::Entry(
                    <&mut FEntry>::try_from(hook)?
                        .attach()
                        .with_context(|| format!("attaching fentry {program} on {target}"))?,
                )
            };
            self.links.push((program, link));
        }
        Ok(())
    }

    /// The refusal reason, when instance routing is unavailable.
    pub(crate) fn refused(&self) -> Option<&str> {
        self.refused.as_deref()
    }

    pub(crate) fn watched(&self, object: PinnedObjectId) -> Option<&WatchedFile> {
        self.watched
            .get(&object)
            .and_then(|state| state.as_ref().ok())
    }

    /// The per-object refusal, when calibration or slot allocation failed.
    pub(crate) fn watch_refusal(&self, object: PinnedObjectId) -> Option<&str> {
        self.watched
            .get(&object)
            .and_then(|state| state.as_ref().err())
            .map(String::as_str)
    }

    /// Ordering I1 for the endpoints about to be linked: calibrate and watch
    /// each new object, then publish every slot's file. Must run before the
    /// endpoint links. Never fails the attach: per-object refusals leave the
    /// slots unmapped (`NO_FILE`).
    pub(crate) fn prepare_targets(
        &mut self,
        ebpf: &mut Ebpf,
        targets: &[Slot],
        objects: &PinnedObjects,
    ) {
        if let Err(error) = self.publish_targets(ebpf, targets, objects) {
            // A SLOT_FILE write failure could leave a stale slot mapping:
            // refuse routing for the whole capture rather than guess.
            self.refused = Some(format!("instance slot publication failed: {error:#}"));
        }
    }

    fn publish_targets(
        &mut self,
        ebpf: &mut Ebpf,
        targets: &[Slot],
        objects: &PinnedObjects,
    ) -> Result<()> {
        for slot in targets {
            let file_slot = if self.refused.is_some() {
                None
            } else {
                if !self.watched.contains_key(&slot.object) {
                    let state = self.watch(ebpf, slot.object, objects);
                    self.watched.insert(slot.object, state);
                }
                self.watched(slot.object).map(|watched| watched.file_slot)
            };
            let mut slot_file: Array<_, u32> =
                Array::try_from(ebpf.map_mut("SLOT_FILE").context("SLOT_FILE map")?)?;
            slot_file
                .set(slot.index, file_slot.map_or(0, |file| file + 1), 0)
                .with_context(|| format!("publishing SLOT_FILE[{}]", slot.index))?;
        }
        Ok(())
    }

    fn watch(
        &mut self,
        ebpf: &mut Ebpf,
        object: PinnedObjectId,
        objects: &PinnedObjects,
    ) -> Result<WatchedFile, String> {
        let path = objects.attach_path_for(object)?;
        let (key, identity) = calibrate(ebpf, &path).map_err(|error| format!("{error:#}"))?;
        let file_slot = match self.keys.get(&key) {
            Some(slot) => *slot,
            None => {
                if self.next_slot >= instance::FILE_SLOTS {
                    return Err(format!(
                        "watched-file ceiling {} reached",
                        instance::FILE_SLOTS
                    ));
                }
                let slot = self.next_slot;
                let mut watched: HashMap<_, InstanceFileKey, u32> = HashMap::try_from(
                    ebpf.map_mut("WATCHED_FILES")
                        .ok_or_else(|| "WATCHED_FILES map".to_string())?,
                )
                .map_err(|error| error.to_string())?;
                watched
                    .insert(key, slot, 0)
                    .map_err(|error| format!("inserting WATCHED_FILES: {error}"))?;
                self.next_slot += 1;
                self.keys.insert(key, slot);
                slot
            }
        };
        Ok(WatchedFile {
            file_slot,
            maps_keys: objects.raw_keys_for(object),
            identity,
        })
    }

    /// The hook programs' statistics, summed. `run_time_ns`/`run_cnt` need
    /// `kernel.bpf_stats_enabled`; `recursion_misses` is always counted.
    pub(crate) fn hook_stats(&self, ebpf: &Ebpf) -> Result<Vec<(&'static str, HookStats)>> {
        INSTANCE_PROGRAMS
            .iter()
            .map(|(program, _)| {
                let fd = ebpf
                    .program(program)
                    .with_context(|| format!("program {program}"))?
                    .fd()
                    .with_context(|| format!("program {program} fd"))?;
                Ok((*program, prog_stats(fd.as_fd())?))
            })
            .collect()
    }
}

/// The calibration protocol: arm `INSTANCE_CALIB` with this thread, map one
/// page of the pinned fd, and require the hook's record of exactly that
/// mapping start. The recorded `{s_dev, i_ino}` is the kernel identity every
/// hook will compute for this file (btrfs anonymous dev, overlay real inode).
/// Calibrates the kernel file key of `path` from the observer's own mapping
/// and records that mapping's `/proc/self/map_files` identity. The key
/// (`s_dev`, `i_ino`) may collide across btrfs subvolumes or overlay layers;
/// the identity is what a scan compares, resolved by the same kernel path as
/// the target's `/proc/<pid>/map_files` entries.
fn calibrate(ebpf: &mut Ebpf, path: &Path) -> Result<(InstanceFileKey, MappedFileIdentity)> {
    let file = File::open(path).with_context(|| format!("reopening {}", path.display()))?;
    // SAFETY: gettid has no preconditions.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
    let mut calib: Array<_, InstanceCalib> = Array::try_from(
        ebpf.map_mut("INSTANCE_CALIB")
            .context("INSTANCE_CALIB map")?,
    )?;
    calib.set(
        0,
        InstanceCalib {
            tid,
            ..InstanceCalib::default()
        },
        0,
    )?;
    let result = (|| -> Result<(InstanceFileKey, MappedFileIdentity)> {
        // SAFETY: a fresh private read-only mapping of an open regular file;
        // it is unmapped below and never dereferenced.
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        ensure!(
            address != libc::MAP_FAILED,
            "calibration mmap: {}",
            std::io::Error::last_os_error()
        );
        let identity = map_file_identity(
            Path::new("/proc/self/map_files"),
            address as u64,
            address as u64 + 4096,
        );
        // SAFETY: exactly the mapping created above.
        unsafe { libc::munmap(address, 4096) };
        let identity = identity.map_err(anyhow::Error::msg)?;
        let record = calib.get(&0, 0)?;
        ensure!(
            record.hits == 1 && record.vm_start == address as u64,
            "calibration hook did not record the observer mapping (hits {})",
            record.hits
        );
        ensure!(record.ino != 0, "calibration recorded inode 0");
        Ok((
            InstanceFileKey {
                dev: record.dev,
                ino: record.ino,
            },
            identity,
        ))
    })();
    calib.set(0, InstanceCalib::default(), 0)?;
    result
}

/// `stat()` of one `map_files` entry: the identity of the file that VMA maps.
fn map_file_identity(
    map_files: &Path,
    start: u64,
    end: u64,
) -> std::result::Result<MappedFileIdentity, String> {
    use std::os::unix::fs::MetadataExt;
    let link = map_files.join(format!("{start:x}-{end:x}"));
    let metadata = std::fs::metadata(&link)
        .map_err(|error| format!("identity of mapped range {start:x}-{end:x}: {error}"))?;
    Ok(MappedFileIdentity {
        dev: metadata.dev(),
        ino: metadata.ino(),
    })
}

/// Readers over the session's instance maps.
pub(crate) struct InstanceMaps<'a> {
    pub(crate) ebpf: &'a Ebpf,
}

impl InstanceMaps<'_> {
    fn array_u64(&self, name: &str, index: u32) -> Result<u64> {
        let map: Array<&MapData, u64> =
            Array::try_from(self.ebpf.map(name).with_context(|| format!("{name} map"))?)?;
        Ok(map.get(&index, 0)?)
    }

    pub(crate) fn global(&self, file_slot: u32) -> Result<u64> {
        self.array_u64("G_EPOCH", file_slot)
    }

    pub(crate) fn fault(&self) -> Result<u64> {
        self.array_u64("INSTANCE_GEN", instance::GEN_FAULT)
    }

    pub(crate) fn sticky(&self) -> Result<u64> {
        self.array_u64("INSTANCE_GEN", instance::GEN_STICKY)
    }

    pub(crate) fn counters(&self) -> Result<InstanceCounters> {
        let map: Array<&MapData, InstanceCounters> = Array::try_from(
            self.ebpf
                .map("INSTANCE_COUNT")
                .context("INSTANCE_COUNT map")?,
        )?;
        Ok(map.get(&0, 0)?)
    }

    /// The process record through its pidfd; `None` when it never mutated a
    /// watched file (epoch 0).
    pub(crate) fn record(&self, pidfd: BorrowedFd<'_>) -> Result<Option<InstanceRecord>> {
        task_storage_lookup(self.ebpf, "PROC_EPOCH", pidfd)
    }

    /// The image cookie through the same pidfd (TASK_COOKIE on the leader).
    pub(crate) fn cookie(&self, pidfd: BorrowedFd<'_>) -> Result<Option<u64>> {
        task_storage_lookup(self.ebpf, "TASK_COOKIE", pidfd)
    }

    /// Raises the fault generation from userspace (hook-program misses):
    /// every later stamp carries the new value, so no call stamped before
    /// the miss can join an observation taken after it.
    pub(crate) fn raise_fault(&self) -> Result<u64> {
        let data = match self.ebpf.map("INSTANCE_GEN").context("INSTANCE_GEN map")? {
            aya::maps::Map::Array(data) => data,
            other => bail!("unexpected INSTANCE_GEN variant {other:?}"),
        };
        raise_mmapped_fault(data.fd().as_fd())
    }
}

/// Atomic fetch-add on the mmapable fault cell, the only userspace writer
/// path that cannot lose a concurrent native compare-exchange raise.
fn raise_mmapped_fault(fd: BorrowedFd<'_>) -> Result<u64> {
    // SAFETY: a shared mapping of the BPF_F_MMAPABLE array's first page.
    let address = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            0,
        )
    };
    ensure!(
        address != libc::MAP_FAILED,
        "mapping INSTANCE_GEN: {}",
        std::io::Error::last_os_error()
    );
    // SAFETY: cell 0 is an aligned u64 inside the mapped page; the kernel
    // side uses compare-exchange on the same cell.
    let cell = unsafe { &*(address as *const std::sync::atomic::AtomicU64) };
    let raised = cell.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    // SAFETY: exactly the mapping created above.
    unsafe { libc::munmap(address, 4096) };
    Ok(raised)
}

fn task_storage_lookup<T: Copy + Default>(
    ebpf: &Ebpf,
    name: &str,
    pidfd: BorrowedFd<'_>,
) -> Result<Option<T>> {
    let data = match ebpf.map(name).with_context(|| format!("{name} map"))? {
        aya::maps::Map::Unsupported(data) => data,
        other => bail!("unexpected {name} map variant {other:?}"),
    };
    let key = pidfd.as_raw_fd();
    let mut value = T::default();
    let attr = BpfMapElementAttr {
        map_fd: data.fd().as_fd().as_raw_fd() as u32,
        key: (&key as *const i32) as u64,
        value: (&mut value as *mut T) as u64,
        ..BpfMapElementAttr::default()
    };
    match bpf_map_element_syscall(BPF_MAP_LOOKUP_ELEM, &attr, size_of_val(&attr)) {
        Ok(()) => Ok(Some(value)),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Err(error) => Err(anyhow!(error)).with_context(|| format!("looking up {name} by pidfd")),
    }
}

/// `bpf_prog_info` prefix through `recursion_misses` (offset 208, Linux
/// 5.12+); the kernel fills only the supplied length.
#[repr(C)]
struct ProgInfoPrefix {
    head: [u8; 192],
    run_time_ns: u64,
    run_cnt: u64,
    recursion_misses: u64,
}

const _: () = assert!(std::mem::offset_of!(ProgInfoPrefix, run_time_ns) == 192);
const _: () = assert!(std::mem::offset_of!(ProgInfoPrefix, recursion_misses) == 208);

#[repr(C)]
#[derive(Default)]
struct ObjInfoAttr {
    bpf_fd: u32,
    info_len: u32,
    info: u64,
}

fn prog_stats(fd: BorrowedFd<'_>) -> Result<HookStats> {
    let mut info = ProgInfoPrefix {
        head: [0; 192],
        run_time_ns: 0,
        run_cnt: 0,
        recursion_misses: 0,
    };
    let attr = ObjInfoAttr {
        bpf_fd: fd.as_raw_fd() as u32,
        info_len: size_of_val(&info) as u32,
        info: (&mut info as *mut ProgInfoPrefix) as u64,
    };
    // SAFETY: BPF_OBJ_GET_INFO_BY_FD (15) with a live attr and buffer.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            15u32,
            &attr as *const ObjInfoAttr,
            size_of_val(&attr),
        )
    };
    if rc == -1 {
        return Err(std::io::Error::last_os_error()).context("BPF_OBJ_GET_INFO_BY_FD");
    }
    Ok(HookStats {
        run_time_ns: info.run_time_ns,
        run_cnt: info.run_cnt,
        recursion_misses: info.recursion_misses,
    })
}

/// One live (process, watched file) scan source for the router's
/// [`stable_scan`](crate::discovery::instances::stable_scan): the record and
/// cookie through the retained pidfd, the global/fault/sticky cells, and the
/// file's ranges from `/proc/PID/maps` selected by its maps-visible keys.
pub(crate) struct LiveScan<'a> {
    pub(crate) maps: InstanceMaps<'a>,
    pub(crate) pidfd: BorrowedFd<'a>,
    pub(crate) pid: u32,
    pub(crate) file_slot: u32,
    pub(crate) maps_keys: &'a [ObjectKey],
    pub(crate) identity: MappedFileIdentity,
}

impl crate::discovery::instances::ScanReader for LiveScan<'_> {
    fn epochs(&mut self) -> std::result::Result<crate::discovery::instances::EpochReading, String> {
        let read = || -> Result<crate::discovery::instances::EpochReading> {
            let cookie = self.maps.cookie(self.pidfd)?.unwrap_or(0);
            let (local, record_flags) = match self.maps.record(self.pidfd)? {
                None => (0, 0),
                Some(record) => (
                    record
                        .slot_plus1
                        .iter()
                        .position(|slot| *slot == u64::from(self.file_slot) + 1)
                        .map_or(0, |index| record.epoch[index]),
                    record.flags,
                ),
            };
            Ok(crate::discovery::instances::EpochReading {
                cookie,
                local,
                record_flags,
                global: self.maps.global(self.file_slot)?,
                fault: self.maps.fault()?,
                sticky: self.maps.sticky()?,
            })
        };
        read().map_err(|error| format!("{error:#}"))
    }

    fn ranges(
        &mut self,
    ) -> std::result::Result<Vec<crate::discovery::instances::MapRange>, String> {
        let bytes = std::fs::read(format!("/proc/{}/maps", self.pid))
            .map_err(|error| format!("reading maps: {error}"))?;
        let entries = p11scope_manifest::maps::parse_maps(&bytes)?;
        let mut ranges = Vec::new();
        for key in self.maps_keys {
            ranges.extend(crate::discovery::instances::ranges_for(
                &entries,
                key.device.major,
                key.device.minor,
                key.inode,
            ));
        }
        let map_files = PathBuf::from(format!("/proc/{}/map_files", self.pid));
        crate::discovery::instances::confirm_identity(ranges, self.identity, |start, end| {
            map_file_identity(&map_files, start, end)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{hooks_disabled_by_env_value, lto_enabled_in_config};

    #[test]
    fn disable_hooks_toggle_reads_only_exact_one() {
        use std::ffi::OsStr;
        assert!(hooks_disabled_by_env_value(Some(OsStr::new("1"))));
        for other in [
            None,
            Some(OsStr::new("")),
            Some(OsStr::new("0")),
            Some(OsStr::new("true")),
            Some(OsStr::new(" 1")),
            Some(OsStr::new("1 ")),
        ] {
            assert!(
                !hooks_disabled_by_env_value(other),
                "{other:?} must not disable the hooks"
            );
        }
    }

    #[test]
    fn lto_config_predicate_matches_only_enabled_selections() {
        for enabled in [
            "CONFIG_LTO_CLANG=y\n",
            "CONFIG_LTO_CLANG_THIN=y\n",
            "CONFIG_LTO_CLANG_FULL=y\n",
            "  CONFIG_LTO_CLANG_THIN=y  \n",
            "CONFIG_PREEMPTION=y\nCONFIG_LTO_CLANG_FULL=y\nCONFIG_LTO_NONE is not set\n",
        ] {
            assert!(lto_enabled_in_config(enabled), "{enabled:?} must read LTO");
        }
        for disabled in [
            "CONFIG_LTO_NONE=y\n",
            "# CONFIG_LTO_CLANG is not set\n",
            "# CONFIG_LTO_CLANG_THIN is not set\n",
            "CONFIG_ARCH_SUPPORTS_LTO_CLANG=y\nCONFIG_ARCH_SUPPORTS_LTO_CLANG_THIN=y\nCONFIG_LTO_NONE=y\n",
            "# Linux/x86 7.0.0-34-generic Kernel Configuration\nCONFIG_PREEMPTION=y\n",
            "",
        ] {
            assert!(
                !lto_enabled_in_config(disabled),
                "{disabled:?} must read non-LTO"
            );
        }
    }
}
