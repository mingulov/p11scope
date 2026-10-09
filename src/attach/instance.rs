//! SPDX-License-Identifier: GPL-3.0-or-later
//! Task 3 Stage A: the Session side of the load-instance continuity witness.
//!
//! - Loads the four native continuity hooks (`uprobe_mmap`, `uprobe_munmap`,
//!   `copy_vma`, `exec_mm_release`) before deferred policy freezes, and attaches
//!   them after all freezes and mandatory lifecycle links. Any
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
use crate::discovery::identity::{PinnedObjectId, PinnedObjects, RetainedInventoryTarget};
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
use std::path::Path;

/// The native hook programs and their kernel attach targets. `copy_vma`'s
/// first argument is a pointer-to-pointer, which no kernel admits as fentry
/// context, so its hook is an fexit reading the returned new VMA (same file,
/// same mm; still under the mremap mmap write lock).
pub(crate) const INSTANCE_PROGRAMS: [(&str, &str); 4] = [
    ("p11_inst_vma_map", "uprobe_mmap"),
    ("p11_inst_vma_unmap", "uprobe_munmap"),
    ("p11_inst_vma_copy", "copy_vma"),
    ("p11_image_exec_release", "exec_mm_release"),
];

/// Hooks attached as fexit; every other instance hook is fentry.
const EXIT_PROGRAMS: [&str; 1] = ["p11_inst_vma_copy"];

/// Only the loader constructs this token. It stays inside one Session's
/// preparation/activation path and is consumed by attachment.
struct LoadedInstancePrograms {
    program_ids: BTreeMap<&'static str, u32>,
}

fn load_instance_programs_with<S>(
    state: &mut S,
    mut load: impl FnMut(&mut S, &'static str, &'static str) -> Result<u32>,
) -> Result<LoadedInstancePrograms> {
    let mut program_ids = BTreeMap::new();
    for (program, target) in INSTANCE_PROGRAMS {
        let id = load(state, program, target)?;
        ensure!(
            id != 0 && !program_ids.values().any(|existing| *existing == id),
            "loaded image hook program IDs unavailable or collide"
        );
        program_ids.insert(program, id);
    }
    Ok(LoadedInstancePrograms { program_ids })
}

fn attach_loaded_instance_programs_with<S>(
    _loaded: LoadedInstancePrograms,
    state: &mut S,
    mut attach: impl FnMut(&mut S, &'static str, &'static str) -> Result<()>,
) -> Result<()> {
    for (program, target) in INSTANCE_PROGRAMS {
        attach(state, program, target)?;
    }
    Ok(())
}

#[derive(Debug)]
enum HookLink {
    Entry(FEntryLinkId),
    Exit(FExitLinkId),
}

/// Produced once during same-object preparation, consumed once after freezes
/// and mandatory lifecycle attachment. No constructor escapes this owner.
pub(super) struct PreparedInstanceTracking {
    programs: std::result::Result<LoadedInstancePrograms, HookPreparationRefusal>,
}
struct HookPreparationRefusal {
    reason: String,
    fail_coverage: bool,
}

/// One watched provider file.
#[derive(Debug)]
pub(crate) struct WatchedFile {
    pub(crate) file_slot: u32,
    /// The maps-visible keys this pinned object is known under; the scan
    /// selects the file's ranges in `/proc/PID/maps` by these.
    pub(crate) maps_keys: Vec<ObjectKey>,
    /// The file's map_files `stat()` identity, recorded at calibration; a
    /// scan keeps only ranges with exactly this identity.
    pub(crate) identity: MappedFileIdentity,
    /// Original opened file and metadata pin, retained independently of the
    /// discovery store. The calibration and every later scan use this object.
    target: RetainedInventoryTarget,
}
impl Clone for WatchedFile {
    fn clone(&self) -> Self {
        Self {
            file_slot: self.file_slot,
            maps_keys: self.maps_keys.clone(),
            identity: self.identity,
            target: self.target.share(),
        }
    }
}
impl WatchedFile {
    pub(super) fn check_unchanged(&self) -> Result<bool, String> {
        self.target.check_unchanged()
    }
}

/// Hook statistics for one fentry program (`BPF_OBJ_GET_INFO_BY_FD`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct HookStats {
    pub(crate) program_id: u32,
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
    program_ids: BTreeMap<&'static str, u32>,
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

    /// Loads hooks only. Never fails ordinary capture: the retained result
    /// names the first refusal and cannot authorize attachment or coverage.
    /// Refusal order is measurement toggle, then policy (Task 1d: metrics
    /// never joins per-call records, so it never pays the hooks), then LTO.
    pub(super) fn prepare(
        ebpf: &mut Ebpf,
        btf: &Btf,
        policy: super::CapturePolicy,
        image_query_refusal: Option<String>,
    ) -> PreparedInstanceTracking {
        let refused = |reason, fail_coverage| PreparedInstanceTracking {
            programs: Err(HookPreparationRefusal {
                reason,
                fail_coverage,
            }),
        };
        if hooks_disabled_by_env() {
            return refused(
                format!(
                    "instance continuity hooks refused: disabled by {DISABLE_HOOKS_ENV}=1 (Stage A overhead measurement)"
                ),
                true,
            );
        }
        if !policy.wants_instance_hooks() {
            return refused(
                "instance continuity hooks refused: aggregate-only (metrics) sessions never join per-call records to load instances (Task 1d overhead gate)"
                    .to_string(),
                false,
            );
        }
        let preparation = (|| {
            if let Some(reason) = image_query_refusal {
                bail!("image continuity query unavailable: {reason}");
            }
            if let Some(reason) = lto_refusal() {
                bail!("{reason}");
            }
            Self::load_hooks(ebpf, btf)
        })();
        PreparedInstanceTracking {
            programs: preparation.map_err(|error| HookPreparationRefusal {
                reason: format!("instance continuity hooks unavailable: {error:#}"),
                fail_coverage: true,
            }),
        }
    }

    /// Consumes the same-object load result. Performs no program loads;
    /// attachment, exact ID/health validation and enable happen only here.
    pub(super) fn start(
        ebpf: &mut Ebpf,
        coverage: &super::image_query::CoverageControl,
        prepared: PreparedInstanceTracking,
    ) -> Self {
        let mut tracking = Self::default();
        let loaded = match prepared.programs {
            Ok(loaded) => loaded,
            Err(refusal) => {
                if refusal.fail_coverage {
                    coverage.fail();
                }
                tracking.refused = Some(refusal.reason);
                return tracking;
            }
        };
        let expected = loaded.program_ids.clone();
        let activation = activate_image_coverage_with(coverage, None, || {
            tracking.attach_hooks(ebpf, loaded)?;
            validate_hook_health_with(
                tracking.links.len(),
                Some(&expected),
                || Ok(std::fs::read_to_string("/proc/sys/kernel/ftrace_enabled")?),
                || tracking.hook_stats(ebpf),
            )
        });
        if let Ok(ids) = &activation {
            tracking.program_ids = ids.clone();
        }
        if let Err(error) = activation {
            coverage.fail();
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

    pub(super) fn audit(
        &self,
        ebpf: &Ebpf,
        coverage: &super::image_query::CoverageControl,
    ) -> Result<()> {
        audit_image_hooks_with(
            coverage,
            self.refused.is_none(),
            self.links.len(),
            &self.program_ids,
            || Ok(std::fs::read_to_string("/proc/sys/kernel/ftrace_enabled")?),
            || self.hook_stats(ebpf),
            || {
                let maps = InstanceMaps { ebpf };
                Ok((maps.sticky()?, maps.fault()?))
            },
        )
    }

    fn load_hooks(ebpf: &mut Ebpf, btf: &Btf) -> Result<LoadedInstancePrograms> {
        ensure!(
            exec_release_proto_is_exact(&btf.to_bytes()),
            "exec_mm_release must be void(task_struct *, mm_struct *)"
        );
        load_instance_programs_with(ebpf, |ebpf, program, target| {
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
            let fd = ebpf
                .program(program)
                .context("loaded image hook program")?
                .fd()?;
            Ok(prog_stats(fd.as_fd())?.program_id)
        })
    }

    fn attach_hooks(&mut self, ebpf: &mut Ebpf, loaded: LoadedInstancePrograms) -> Result<()> {
        attach_loaded_instance_programs_with(loaded, ebpf, |ebpf, program, target| {
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
            Ok(())
        })
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
        let target = objects.retain_inventory_target(object)?;
        let path = target.attach_path();
        let (key, identity) = calibrate(ebpf, &path).map_err(|error| format!("{error:#}"))?;
        if !target.check_unchanged()? {
            return Err("watched object changed during calibration".into());
        }
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
            target,
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

/// Verify the actual BTF prototype rather than accepting the function name
/// alone. This is separate from the no-LTO cross-file call coverage premise.
fn exec_release_proto_is_exact(raw: &[u8]) -> bool {
    let word = |bytes: &[u8], at: usize| -> Option<u32> {
        Some(u32::from_le_bytes(
            bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
        ))
    };
    let checked = || -> Option<bool> {
        if raw.get(..4)? != [0x9f, 0xeb, 1, 0] {
            return Some(false);
        }
        let header = word(raw, 4)? as usize;
        if header < 24 {
            return Some(false);
        }
        let type_start = header.checked_add(word(raw, 8)? as usize)?;
        let type_end = type_start.checked_add(word(raw, 12)? as usize)?;
        let string_start = header.checked_add(word(raw, 16)? as usize)?;
        let string_end = string_start.checked_add(word(raw, 20)? as usize)?;
        let types = raw.get(type_start..type_end)?;
        let strings = raw.get(string_start..string_end)?;
        let name = |offset: u32| -> Option<&[u8]> {
            let tail = strings.get(offset as usize..)?;
            Some(&tail[..tail.iter().position(|byte| *byte == 0)?])
        };
        let mut nodes = vec![&[][..]];
        let mut cursor = 0usize;
        while cursor < types.len() {
            let record = types.get(cursor..)?;
            let info = word(record, 4)?;
            let kind = (info >> 24) & 31;
            let count = (info & 65535) as usize;
            let extra = match kind {
                0 | 2 | 7 | 8 | 9 | 10 | 11 | 12 | 16 | 18 => 0,
                1 | 14 | 17 => 4,
                3 => 12,
                4 | 5 | 15 | 19 => count.checked_mul(12)?,
                6 | 13 => count.checked_mul(8)?,
                _ => return Some(false),
            };
            let length = 12usize.checked_add(extra)?;
            nodes.push(record.get(..length)?);
            cursor = cursor.checked_add(length)?;
        }
        let resolve = |mut id: u32| -> Option<&[u8]> {
            for _ in 0..32 {
                let node = *nodes.get(id as usize)?;
                let kind = (word(node, 4)? >> 24) & 31;
                if !matches!(kind, 8 | 9 | 10 | 11 | 18) {
                    return Some(node);
                }
                id = word(node, 8)?;
            }
            None
        };
        let pointee = |id: u32, wanted: &[u8]| -> Option<bool> {
            let pointer = resolve(id)?;
            if (word(pointer, 4)? >> 24) & 31 != 2 {
                return Some(false);
            }
            let target = resolve(word(pointer, 8)?)?;
            Some((word(target, 4)? >> 24) & 31 == 4 && name(word(target, 0)?)? == wanted)
        };
        let mut functions = nodes.iter().skip(1).filter(|node| {
            word(node, 4).is_some_and(|info| (info >> 24) & 31 == 12)
                && word(node, 0).and_then(name) == Some(b"exec_mm_release".as_slice())
        });
        let function = functions.next()?;
        if functions.next().is_some() {
            return Some(false);
        }
        let proto = resolve(word(function, 8)?)?;
        if word(proto, 4)? != (13 << 24 | 2) || word(proto, 8)? != 0 {
            return Some(false);
        }
        Some(pointee(word(proto, 16)?, b"task_struct")? && pointee(word(proto, 24)?, b"mm_struct")?)
    };
    checked().unwrap_or(false)
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

/// Bounded checked CAS on the mmapable fault cell, the only userspace writer
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
    let raised = raise_fault_cell(cell);
    // SAFETY: exactly the mapping created above.
    unsafe { libc::munmap(address, 4096) };
    raised
}

fn raise_fault_cell(cell: &std::sync::atomic::AtomicU64) -> Result<u64> {
    use std::sync::atomic::Ordering;
    let mut seen = cell.load(Ordering::SeqCst);
    for _ in 0..8 {
        ensure!(
            seen <= u64::from(u32::MAX),
            "instance fault generation exhausted"
        );
        let next = seen + 1;
        match cell.compare_exchange(seen, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => {
                ensure!(
                    next <= u64::from(u32::MAX),
                    "instance fault generation exhausted"
                );
                return Ok(next);
            }
            Err(current) => seen = current,
        }
    }
    bail!("instance fault generation contention")
}

#[cfg(test)]
mod fault_raise_tests {
    use super::raise_fault_cell;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};

    #[test]
    fn healthy_fault_raise_updates_the_real_atomic_cell() {
        let cell = AtomicU64::new(41);
        assert_eq!(raise_fault_cell(&cell).unwrap(), 42);
        assert_eq!(cell.load(Ordering::SeqCst), 42);
    }

    #[test]
    fn last_representable_fault_raise_then_sentinel_refuses() {
        let cell = AtomicU64::new(u64::from(u32::MAX) - 1);
        assert_eq!(raise_fault_cell(&cell).unwrap(), u64::from(u32::MAX));
        assert!(raise_fault_cell(&cell).is_err());
        assert_eq!(cell.load(Ordering::SeqCst), u64::from(u32::MAX) + 1);
        assert!(raise_fault_cell(&cell).is_err());
        assert_eq!(cell.load(Ordering::SeqCst), u64::from(u32::MAX) + 1);
    }

    #[test]
    fn fault_raise_never_moves_an_unrepresentable_cell() {
        let cell = AtomicU64::new(u64::from(u32::MAX) + 1);
        assert!(raise_fault_cell(&cell).is_err());
        assert_eq!(cell.load(Ordering::SeqCst), u64::from(u32::MAX) + 1);
    }

    #[test]
    fn fault_raise_u64_max_returns_an_error_without_panic_or_wrap() {
        let cell = AtomicU64::new(u64::MAX);
        let result = std::panic::catch_unwind(|| raise_fault_cell(&cell));
        assert!(
            matches!(result, Ok(Err(_))),
            "exhaustion must return an ordinary refusal"
        );
        assert_eq!(cell.load(Ordering::SeqCst), u64::MAX);
    }

    #[test]
    fn competing_fault_writers_never_reopen_an_exhausted_era() {
        let cell = Arc::new(AtomicU64::new(u64::from(u32::MAX) - 1));
        let barrier = Arc::new(Barrier::new(4));
        let writers: Vec<_> = (0..3)
            .map(|_| {
                let cell = Arc::clone(&cell);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    raise_fault_cell(&cell)
                })
            })
            .collect();
        barrier.wait();
        let results: Vec<_> = writers
            .into_iter()
            .map(|writer| writer.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert!(
            results
                .iter()
                .filter_map(|result| result.as_ref().ok())
                .all(|raised| *raised == u64::from(u32::MAX))
        );
        assert_eq!(cell.load(Ordering::SeqCst), u64::from(u32::MAX) + 1);
        assert!(raise_fault_cell(&cell).is_err());
    }
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
    let mut attr = ObjInfoAttr {
        bpf_fd: fd.as_raw_fd() as u32,
        info_len: size_of_val(&info) as u32,
        info: (&mut info as *mut ProgInfoPrefix) as u64,
    };
    // SAFETY: BPF_OBJ_GET_INFO_BY_FD (15) with a live attr and buffer.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            15u32,
            &mut attr as *mut ObjInfoAttr,
            size_of_val(&attr),
        )
    };
    if rc == -1 {
        return Err(std::io::Error::last_os_error()).context("BPF_OBJ_GET_INFO_BY_FD");
    }
    decode_prog_stats(&info, attr.info_len)
}

fn decode_prog_stats(info: &ProgInfoPrefix, reported_len: u32) -> Result<HookStats> {
    ensure!(
        reported_len >= 216,
        "program info omits recursion-miss statistics"
    );
    Ok(HookStats {
        program_id: u32::from_ne_bytes(info.head[4..8].try_into().unwrap()),
        run_time_ns: info.run_time_ns,
        run_cnt: info.run_cnt,
        recursion_misses: info.recursion_misses,
    })
}

/// The production health decision shared by activation and later audits.
fn validate_hook_health_with(
    link_count: usize,
    expected: Option<&BTreeMap<&'static str, u32>>,
    read_ftrace: impl FnOnce() -> Result<String>,
    read_stats: impl FnOnce() -> Result<Vec<(&'static str, HookStats)>>,
) -> Result<BTreeMap<&'static str, u32>> {
    ensure!(
        link_count == INSTANCE_PROGRAMS.len(),
        "partial image hook attachment"
    );
    ensure!(
        read_ftrace()?.trim() == "1",
        "ftrace must be enabled for image continuity"
    );
    let mut ids = BTreeMap::new();
    for (name, stats) in read_stats()? {
        ensure!(
            stats.program_id != 0
                && stats.recursion_misses == 0
                && INSTANCE_PROGRAMS
                    .iter()
                    .any(|(required, _)| *required == name)
                && ids.insert(name, stats.program_id).is_none(),
            "image hook identity/statistics unavailable"
        );
        if let Some(expected) = expected {
            ensure!(
                expected.get(name) == Some(&stats.program_id),
                "image hook identity changed"
            );
        }
    }
    ensure!(
        ids.len() == INSTANCE_PROGRAMS.len(),
        "missing image hook statistics"
    );
    ensure!(
        ids.values()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == ids.len(),
        "image hook program IDs collide"
    );
    Ok(ids)
}

fn activate_image_coverage_with(
    coverage: &super::image_query::CoverageControl,
    query_refusal: Option<&str>,
    attach_and_read: impl FnOnce() -> Result<BTreeMap<&'static str, u32>>,
) -> Result<BTreeMap<&'static str, u32>> {
    let result = (|| {
        if let Some(reason) = query_refusal {
            bail!("image continuity query unavailable: {reason}");
        }
        let ids = attach_and_read()?;
        coverage.enable()?;
        Ok(ids)
    })();
    if result.is_err() {
        coverage.fail();
    }
    result
}

pub(super) fn audit_image_hooks_with(
    coverage: &super::image_query::CoverageControl,
    active: bool,
    link_count: usize,
    expected: &BTreeMap<&'static str, u32>,
    read_ftrace: impl FnOnce() -> Result<String>,
    read_stats: impl FnOnce() -> Result<Vec<(&'static str, HookStats)>>,
    read_faults: impl FnOnce() -> Result<(u64, u64)>,
) -> Result<()> {
    let result = (|| {
        ensure!(active && coverage.enabled(), "image continuity unavailable");
        validate_hook_health_with(link_count, Some(expected), read_ftrace, read_stats)?;
        let (sticky, fault) = read_faults()?;
        ensure!(
            sticky == 0 && fault <= u64::from(u32::MAX),
            "instance continuity fault/exhaustion"
        );
        ensure!(
            coverage.enabled(),
            "image continuity failed during health audit"
        );
        Ok(())
    })();
    if result.is_err() {
        coverage.fail();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{exec_release_proto_is_exact, hooks_disabled_by_env_value, lto_enabled_in_config};

    fn healthy_hook_stats() -> Vec<(&'static str, super::HookStats)> {
        super::INSTANCE_PROGRAMS
            .iter()
            .enumerate()
            .map(|(index, (name, _))| {
                let mut info = super::ProgInfoPrefix {
                    head: [0; 192],
                    run_time_ns: 0,
                    run_cnt: 0,
                    recursion_misses: 0,
                };
                info.head[4..8].copy_from_slice(&(index as u32 + 1).to_ne_bytes());
                (*name, super::decode_prog_stats(&info, 216).unwrap())
            })
            .collect()
    }

    #[test]
    fn production_program_info_refuses_shortened_statistics() {
        let info = super::ProgInfoPrefix {
            head: [0; 192],
            run_time_ns: 0,
            run_cnt: 0,
            recursion_misses: 0,
        };
        for length in [0, 192, 208, 215] {
            assert!(super::decode_prog_stats(&info, length).is_err());
        }
        assert!(super::decode_prog_stats(&info, 216).is_ok());
    }

    #[test]
    fn production_hook_health_failures_permanently_latch_coverage() {
        let expected = healthy_hook_stats()
            .into_iter()
            .map(|(name, stats)| (name, stats.program_id))
            .collect();
        for case in 0..11 {
            let coverage = super::super::image_query::CoverageControl::test_owner(true);
            let mut stats = healthy_hook_stats();
            if case == 3 {
                stats.pop();
            }
            if case == 4 {
                stats[0].1.program_id += 100;
            }
            if case == 5 {
                stats[0].1.program_id = 0;
            }
            let result = super::audit_image_hooks_with(
                &coverage,
                case != 7,
                if case == 6 { 3 } else { 4 },
                &expected,
                || {
                    if case == 0 {
                        Err(anyhow::anyhow!("unreadable ftrace"))
                    } else {
                        Ok(if case == 1 { "0" } else { "1" }.into())
                    }
                },
                || {
                    if case == 2 {
                        Err(anyhow::anyhow!("unreadable program info"))
                    } else {
                        Ok(stats)
                    }
                },
                || {
                    if case == 10 {
                        coverage.fail();
                    }
                    Ok((
                        u64::from(case == 8),
                        if case == 9 {
                            u64::from(u32::MAX) + 1
                        } else {
                            0
                        },
                    ))
                },
            );
            assert!(result.is_err(), "health case {case} was accepted");
            assert!(!coverage.enabled());
            assert!(coverage.enable().is_err());
        }
        for missed in 0..super::INSTANCE_PROGRAMS.len() {
            let coverage = super::super::image_query::CoverageControl::test_owner(true);
            let mut stats = healthy_hook_stats();
            stats[missed].1.recursion_misses = 1;
            assert!(
                super::audit_image_hooks_with(
                    &coverage,
                    true,
                    4,
                    &expected,
                    || Ok("1".into()),
                    || Ok(stats),
                    || Ok((0, 0)),
                )
                .is_err()
            );
            // Ordinary fault values are separate; a later reset never re-enables.
            assert!(
                super::audit_image_hooks_with(
                    &coverage,
                    true,
                    4,
                    &expected,
                    || Ok("1".into()),
                    || Ok(healthy_hook_stats()),
                    || Ok((0, 0)),
                )
                .is_err()
            );
            assert!(coverage.enable().is_err());
        }
    }

    #[test]
    fn optional_hook_load_refusal_never_attaches_and_complete_load_waits_for_activation() {
        for fail in 0..=super::INSTANCE_PROGRAMS.len() {
            let coverage = super::super::image_query::CoverageControl::test_owner(false);
            let mut calls = Vec::new();
            let mut loaded_count = 0;
            let prepared = super::load_instance_programs_with(&mut calls, |calls, program, _| {
                assert!(calls.iter().all(|(operation, _)| *operation == "load"));
                calls.push(("load", program));
                if loaded_count == fail {
                    anyhow::bail!("owned load refusal: {program}");
                }
                loaded_count += 1;
                Ok(loaded_count as u32)
            });
            assert!(!coverage.enabled());
            let health_called = std::cell::Cell::new(false);
            let result = super::activate_image_coverage_with(&coverage, None, || {
                let loaded = prepared?;
                let expected = loaded.program_ids.clone();
                super::attach_loaded_instance_programs_with(
                    loaded,
                    &mut calls,
                    |calls, program, _| {
                        assert_eq!(loaded_count, super::INSTANCE_PROGRAMS.len());
                        calls.push(("attach", program));
                        Ok(())
                    },
                )?;
                health_called.set(true);
                super::validate_hook_health_with(
                    super::INSTANCE_PROGRAMS.len(),
                    Some(&expected),
                    || Ok("1".into()),
                    || Ok(healthy_hook_stats()),
                )
            });
            if fail < super::INSTANCE_PROGRAMS.len() {
                assert_eq!(
                    result.unwrap_err().to_string(),
                    format!("owned load refusal: {}", super::INSTANCE_PROGRAMS[fail].0)
                );
                assert_eq!(calls.len(), fail + 1);
                assert!(!health_called.get());
                assert!(!coverage.enabled());
                assert!(coverage.enable().is_err());
            } else {
                assert_eq!(result.unwrap().len(), super::INSTANCE_PROGRAMS.len());
                assert_eq!(calls.len(), super::INSTANCE_PROGRAMS.len() * 2);
                assert!(health_called.get());
                assert!(coverage.enabled());
            }
        }
    }

    #[test]
    fn loaded_hook_identity_change_refuses_activation_before_enable() {
        let coverage = super::super::image_query::CoverageControl::test_owner(false);
        let mut next = 0;
        let loaded = super::load_instance_programs_with(&mut next, |next, _, _| {
            *next += 1;
            Ok(*next)
        })
        .unwrap();
        let expected = loaded.program_ids.clone();
        let result = super::activate_image_coverage_with(&coverage, None, || {
            super::attach_loaded_instance_programs_with(loaded, &mut (), |_, _, _| Ok(()))?;
            let mut stats = healthy_hook_stats();
            stats[3].1.program_id += 100;
            super::validate_hook_health_with(
                super::INSTANCE_PROGRAMS.len(),
                Some(&expected),
                || Ok("1".into()),
                || Ok(stats),
            )
        });
        assert_eq!(
            result.unwrap_err().to_string(),
            "image hook identity changed"
        );
        assert!(!coverage.enabled());
        assert!(coverage.enable().is_err());
    }

    #[test]
    fn production_activation_requires_query_all_hooks_and_healthy_reads() {
        for case in 0..4 {
            let coverage = super::super::image_query::CoverageControl::test_owner(false);
            let called = std::cell::Cell::new(false);
            let result = super::activate_image_coverage_with(
                &coverage,
                (case == 0).then_some("iterator verifier refusal"),
                || {
                    called.set(true);
                    if case == 1 {
                        anyhow::bail!("partial hook load/attach");
                    }
                    super::validate_hook_health_with(
                        if case == 2 { 3 } else { 4 },
                        None,
                        || Ok("1".into()),
                        || Ok(healthy_hook_stats()),
                    )
                },
            );
            if case == 3 {
                assert_eq!(result.unwrap().len(), 4);
                assert!(coverage.enabled());
            } else {
                assert!(result.is_err());
                assert!(!coverage.enabled());
                assert!(coverage.enable().is_err());
            }
            assert_eq!(called.get(), case != 0);
        }
    }

    #[test]
    fn watched_file_retains_unlinked_original_and_rejects_replacement() {
        use crate::discovery::identity::test_fixture::real_scan_pin;
        use std::os::unix::fs::MetadataExt as _;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provider");
        std::fs::write(&path, b"original bytes").unwrap();
        let pins = real_scan_pin(&path, None, 1, "original-digest");
        let object = pins.pinned().next().unwrap().id;
        let original = pins.file_for(object).unwrap().metadata().unwrap();
        let watched = super::WatchedFile {
            file_slot: 0,
            maps_keys: pins.raw_keys_for(object),
            identity: crate::discovery::instances::MappedFileIdentity {
                dev: original.dev(),
                ino: original.ino(),
            },
            target: pins.retain_inventory_target(object).unwrap(),
        };
        let scan_owner = watched.clone();
        drop(pins);
        assert!(watched.check_unchanged().unwrap());
        assert!(scan_owner.check_unchanged().unwrap());
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"replacement bytes").unwrap();
        let retained = scan_owner.target.retirement_lease();
        assert_eq!(retained.metadata().unwrap().ino(), original.ino());
        assert_ne!(std::fs::metadata(&path).unwrap().ino(), original.ino());
        // Unlink changed the original's ctime. Never authorize the replacement
        // merely because it occupies the old pathname.
        assert!(!scan_owner.check_unchanged().unwrap());
        assert!(!watched.check_unchanged().unwrap());
    }

    #[test]
    fn image_hook_requires_the_exact_exec_release_prototype() {
        let strings = b"\0task_struct\0mm_struct\0exec_mm_release\0";
        let words = [
            1,
            4 << 24,
            1, // task_struct
            0,
            2 << 24,
            1, // pointer to task
            13,
            4 << 24,
            1, // mm_struct
            0,
            2 << 24,
            3, // pointer to mm
            0,
            (13 << 24) | 2,
            0,
            0,
            2,
            0,
            4, // two-argument void proto
            23,
            (12 << 24) | 1,
            5, // externally defined function
        ];
        let types: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let mut bytes = vec![0x9f, 0xeb, 1, 0];
        for word in [
            24,
            0,
            types.len() as u32,
            types.len() as u32,
            strings.len() as u32,
        ] {
            bytes.extend(word.to_le_bytes());
        }
        bytes.extend(types);
        bytes.extend(strings);
        assert!(exec_release_proto_is_exact(&bytes));
        let mut wrong = bytes.clone();
        wrong[24 + 48 + 16..24 + 48 + 20].copy_from_slice(&4u32.to_le_bytes());
        assert!(!exec_release_proto_is_exact(&wrong));
        for truncated in 0..bytes.len() {
            assert!(!exec_release_proto_is_exact(&bytes[..truncated]));
        }
    }

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
