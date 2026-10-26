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

use super::{BPF_MAP_LOOKUP_ELEM, BpfMapElementAttr, StaticRoots, bpf_map_element_syscall};
use crate::discovery::identity::{PinnedObjectId, PinnedObjects, RetainedInventoryTarget};
use crate::discovery::instances::MappedFileIdentity;
use crate::plan::Slot;
use anyhow::{Context as _, Result, anyhow, bail, ensure};
use aya::maps::{Array, HashMap, MapData, MapType};
use aya::programs::fentry::FEntryLinkId;
use aya::programs::fexit::FExitLinkId;
use aya::programs::{FEntry, FExit};
use aya::{Btf, Ebpf};
use p11scope_ebpf_common::{
    InstanceCalib, InstanceCounters, InstanceFileKey, InstanceRecord, JournalAdmissionControl,
    instance,
};
use p11scope_manifest::maps::{Device, ObjectKey};
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
    /// The only production way to build a watched file: the scan
    /// selects ranges by the pin's raw keys plus the calibration
    /// kernel key (pre-6.8 overlay maps show the backing identity;
    /// see [`maps_keys_for_watch`]). `watch()` delegates here, so the
    /// key-joining rule is pinned by the default-run
    /// `watched_file_constructor_keeps_raw_and_calibration_keys`
    /// test; `watch()` itself needs a loaded hook (calibration
    /// requires exactly one `INSTANCE_CALIB` hit) and so cannot run
    /// unprivileged.
    fn for_watch(
        file_slot: u32,
        raw_keys: Vec<ObjectKey>,
        calib: InstanceFileKey,
        identity: MappedFileIdentity,
        target: RetainedInventoryTarget,
    ) -> Self {
        Self {
            file_slot,
            maps_keys: maps_keys_for_watch(raw_keys, calib),
            identity,
            target,
        }
    }

    pub(super) fn check_unchanged(&self) -> Result<bool, String> {
        self.target.check_unchanged()
    }

    pub(super) fn retained_target(&self) -> RetainedInventoryTarget {
        self.target.share()
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

    /// Transfer every original hook owner out of this Session's Aya registry.
    /// FEntry/FExit wrappers are exactly FdLink-backed; conversion is infallible
    /// and does not close/reopen the link. A failed take leaves the residual
    /// owner in Aya, and terminal cleanup must retain the complete Session.
    pub(super) fn take_owned_hooks(
        &mut self,
        ebpf: &mut Ebpf,
    ) -> Vec<Result<(super::OwnedLink, super::ProducerProgram)>> {
        std::mem::take(&mut self.links)
            .into_iter()
            .map(|(program, link)| {
                let hook = ebpf.program_mut(program).with_context(|| {
                    format!("program {program} missing during instance hook retirement")
                })?;
                let owned = match link {
                    HookLink::Entry(id) => super::OwnedLink::Fd(
                        <&mut FEntry>::try_from(hook)?
                            .take_link(id)
                            .with_context(|| format!("taking original fentry {program}"))?
                            .into(),
                    ),
                    HookLink::Exit(id) => super::OwnedLink::Fd(
                        <&mut FExit>::try_from(hook)?
                            .take_link(id)
                            .with_context(|| format!("taking original fexit {program}"))?
                            .into(),
                    ),
                };
                Ok((owned, super::ProducerProgram::InstanceHook(program)))
            })
            .collect()
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
        Self::start_with_failure_ownership(ebpf, coverage, prepared, false)
    }

    /// Selected preparation owns every partial hook acquisition through the
    /// actual terminal cleanup worker. A refused hook never detaches inline.
    pub(super) fn start_selected(
        ebpf: &mut Ebpf,
        coverage: &super::image_query::CoverageControl,
        prepared: PreparedInstanceTracking,
    ) -> Self {
        Self::start_with_failure_ownership(ebpf, coverage, prepared, true)
    }

    fn start_with_failure_ownership(
        ebpf: &mut Ebpf,
        coverage: &super::image_query::CoverageControl,
        prepared: PreparedInstanceTracking,
        retain_failed_hooks: bool,
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
            if retain_failed_hooks {
                return tracking;
            }
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
        let host =
            super::host_btf::shared().context("loading required vmlinux BTF for instance hooks")?;
        validate_exec_release_proto(host, btf)?;
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
        Ok(WatchedFile::for_watch(
            file_slot,
            objects.raw_keys_for(object),
            key,
            identity,
            target,
        ))
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
fn validate_exec_release_proto(host: &super::host_btf::HostBtf, btf: &Btf) -> Result<()> {
    let raw = host
        .original_bytes_for(btf)
        .context("instance hook BTF differs from cached host BTF")?;
    ensure!(
        exec_release_proto_is_exact(raw),
        "exec_mm_release must be void(task_struct *, mm_struct *)"
    );
    Ok(())
}

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

/// Maps-selection keys for a watched object: the pin's raw keys plus the
/// calibration kernel key (`s_dev`, `i_ino`). Before upstream 3efdc78fdc21
/// (v6.8), /proc/PID/maps shows an overlayfs-backed mapping under the
/// backing file's (device, inode), which the mountinfo-derived raw key
/// never matches; the calibration pair is exactly what those kernels show
/// (the same `f_inode` both sides; probed on 6.6.157 for upper-only and
/// lower-layer files). On 6.8+ the raw key matches and the calibration key
/// is normally dead, but it can still select another mount's ranges:
/// pre-6.8 every mount of the same lower file shares the backing maps line
/// (probed `(52, 11)` on both mounts on 6.6); on 6.8+ only by numeric
/// coincidence. Identity confirmation still gates every selected
/// candidate, so such extras only cost a few refused `map_files` stats —
/// never a false join (a second mount compares unequal: `(66, 11)` vs
/// `(68, 11)` on 6.6, `(69, 11)` vs `(71, 11)` on 7.0).
pub(super) fn maps_keys_for_watch(
    mut raw: Vec<ObjectKey>,
    calib: InstanceFileKey,
) -> Vec<ObjectKey> {
    // Kernel kdev_t decoding (12-bit major at bits 20-31, 20-bit minor):
    // the hook reports the raw `s_dev`, not a userspace `st_dev`, so
    // `libc::major`/`libc::minor` would misread it.
    raw.push(ObjectKey {
        device: Device {
            major: (calib.dev >> 20) & 0xfff,
            minor: calib.dev & 0xfffff,
        },
        inode: calib.ino,
    });
    raw.sort();
    raw.dedup();
    raw
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

/// Issuance capability for native birth evidence, never birth grants.
/// Only Session-owned attach code can mint one (private field, constructed
/// solely by the observation sites in this module). Production grant issuance
/// separately requires the opaque validated H0/absence association.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionGrantToken(());

/// Finite birth-row read failure: the native rows could not be read.
/// Live map errors and short fixture buffers alike refuse; callers map
/// both to [`BirthObservationRefusal::RowUnreadable`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BirthRowError {
    /// The native row lookup failed (map error, detached object) or
    /// the row is absent (missing storage refuses; it is not zero).
    Unreadable,
    /// The row bytes are shorter than the native row (fixture
    /// corruption; native rows are always complete).
    Short,
}

/// Native birth-row reader: the observation pulls the PROC_EPOCH
/// marker row and the admission control row through this, never
/// receiving caller-built structs. Production reads live maps
/// ([`LiveBirthRows`], UNRUN); tests read fixture bytes the real
/// native leaves published.
pub(crate) trait BirthRowReader {
    fn read_marker_row(&mut self) -> std::result::Result<InstanceRecord, BirthRowError>;
    fn read_admission_control(
        &mut self,
    ) -> std::result::Result<p11scope_ebpf_common::JournalAdmissionControl, BirthRowError>;
}

/// Finite birth-observation refusal: which genuine Session producer
/// failed. Observation refuses; nothing is minted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BirthObservationRefusal {
    CurrentPartition,
    StreamCut,
    AbsenceHistory,
    /// The PROC_EPOCH marker readback is not READY naming the admitted
    /// image's exec id (unpublished, DIRTY, invalid, or another exec).
    MarkerNotReady,
    /// The admission control row trips the failed latch.
    LatchTripped,
    /// The admission control row spent its permit cap.
    SpentExhausted,
    /// The held pidfd no longer pins the birth's process
    /// (exited/reused), or never had a start-time basis to bind.
    CustodyLost,
    /// The sealed attachment names another domain than the admission.
    AttachmentMismatch,
    /// The marker word is not unmarked: something published (READY)
    /// or poisoned (DIRTY) this birth's marker, so absence is unproven.
    MarkerPublished,
    /// The native birth rows could not be read (map error, short
    /// buffer): an unreadable row is never clean evidence.
    RowUnreadable,
    /// The custody binding does not name the admitted
    /// domain/image/caller: the held pidfd is not bound to the
    /// admitted image.
    BindingMismatch,
    /// The observed attach generation is not the sealed closure's
    /// minted generation: the row's `exec_attach_gen` (exec birth)
    /// or the negative scan's attach cell (absence birth) ran under
    /// another closure.
    GenerationMismatch,
    /// The negative witness or the appearance names another process,
    /// domain, or file: not this birth's witness pair.
    AppearanceForeign,
    /// The appearance epochs did not strictly advance past the
    /// negative: no un-journaled exec to backfill.
    AppearanceNotAdvanced,
    /// The real router refused the appearance (already observed at
    /// these epochs, stale era, retired): no accepted mapping.
    AppearanceRejected,
    /// The negative witness is not current and consistent with the
    /// appearance: its retained publication fence is not the
    /// router's current fence, or the appearance's fence is not the
    /// negative's. An absence witness must not bridge a gap that
    /// invalidated its authority; the positive stays withheld.
    NegativeFenceMismatch,
}

/// Only a genuine H3 admission can construct this retained association.
/// Keep no S1 payload and no caller-selected scalar constructor.
pub(crate) struct BirthAdmissionBinding {
    domain: super::capture::NativeDomainId,
    image: p11scope_ebpf_common::ImageIdentity,
    caller: crate::discovery::caller_registry::CallerId,
}
impl BirthAdmissionBinding {
    pub(crate) fn from_admitted(
        admitted: &crate::discovery::caller_registry::instance_input::AdmittedInstanceCall,
    ) -> Self {
        let (domain, image, _, caller) = admitted.journal_binding();
        Self {
            domain,
            image,
            caller,
        }
    }
}

/// Shared birth producers: the admitted domain and image, the
/// admission authority's custody binding (the held pidfd bound to the
/// admitted image, live with a start-time basis), and the admission
/// control row's latch and spent bound. Every word is read or derived
/// here; nothing is supplied. The control row is passed in after the
/// caller read it through the birth-row reader.
fn common_birth_words(
    control: &p11scope_ebpf_common::JournalAdmissionControl,
    binding: &crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding,
    attachment: &super::AttachedSemanticSet,
    admitted: &crate::discovery::caller_registry::instance_input::AdmittedInstanceCall,
) -> std::result::Result<((u64, u64), u64), BirthObservationRefusal> {
    common_retained_birth_words(
        control,
        binding,
        attachment,
        &BirthAdmissionBinding::from_admitted(admitted),
    )
}

fn common_retained_birth_words(
    control: &p11scope_ebpf_common::JournalAdmissionControl,
    binding: &crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding,
    attachment: &super::AttachedSemanticSet,
    admitted: &BirthAdmissionBinding,
) -> std::result::Result<((u64, u64), u64), BirthObservationRefusal> {
    let (domain, image, caller) = (admitted.domain, admitted.image, admitted.caller);
    if attachment.domain() != domain {
        return Err(BirthObservationRefusal::AttachmentMismatch);
    }
    // Bind the held pidfd to the admitted image: the binding must name
    // the admitted domain, image and caller, and its pin is the custody
    // for exactly those. A live pin for another image is not custody.
    if !binding.scope_current()
        || binding.domain() != domain
        || binding.image() != image
        || binding.caller() != caller
    {
        return Err(BirthObservationRefusal::BindingMismatch);
    }
    let custody = binding.pin();
    match custody.original_generation_state() {
        Ok(crate::process::OriginalGenerationState::Current) => {}
        _ => return Err(BirthObservationRefusal::CustodyLost),
    }
    let custody_word = custody
        .start_time()
        .ok_or(BirthObservationRefusal::CustodyLost)?;
    if control.failed != 0 {
        return Err(BirthObservationRefusal::LatchTripped);
    }
    if control.spent >= p11scope_ebpf_common::journal_marker::MARKER_ADMIT_CAP {
        return Err(BirthObservationRefusal::SpentExhausted);
    }
    Ok(((image.task_cookie, image.exec_id), custody_word))
}

/// Re-read native truth for a retained admission. This is freshness evidence,
/// not birth authority; only the H0 owner can authorize an initial birth after
/// validating its original candidate and any required committed absence.
pub(crate) fn observe_retained_birth(
    rows: &mut impl BirthRowReader,
    binding: &crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding,
    attachment: &super::AttachedSemanticSet,
    admitted: &BirthAdmissionBinding,
    birth: crate::semantics_objects::journal::BirthKind,
) -> std::result::Result<
    crate::semantics_objects::journal::SessionBirthEvidence,
    BirthObservationRefusal,
> {
    use crate::semantics_objects::journal::BirthKind;
    let record = rows
        .read_marker_row()
        .map_err(|_| BirthObservationRefusal::RowUnreadable)?;
    let control = rows
        .read_admission_control()
        .map_err(|_| BirthObservationRefusal::RowUnreadable)?;
    let (image, custody) = common_retained_birth_words(&control, binding, attachment, admitted)?;
    match birth {
        BirthKind::ExecMarker => {
            if p11scope_ebpf_common::journal_marker::read_word(record.journal_bootstrap)
                != p11scope_ebpf_common::journal_marker::MarkerRead::Ready(image.1)
            {
                return Err(BirthObservationRefusal::MarkerNotReady);
            }
            if record.exec_attach_gen != attachment.generation() {
                return Err(BirthObservationRefusal::GenerationMismatch);
            }
        }
        BirthKind::AbsenceAppearance if record.journal_bootstrap != 0 => {
            return Err(BirthObservationRefusal::MarkerPublished);
        }
        BirthKind::AbsenceAppearance => {}
    }
    let token = SessionGrantToken(());
    let evidence = crate::semantics_objects::journal::SessionBirthEvidence::issue(
        &token,
        image,
        record.journal_bootstrap,
        control.failed,
        attachment.generation(),
        custody,
    );
    Ok(evidence)
}

/// Session-owned exec-marker birth observation. The producers are
/// genuine Session observations end to end: the PROC_EPOCH marker row
/// and admission control row pulled through the birth-row reader (the
/// marker read back READY naming the admitted image's exec id, the
/// row's `exec_attach_gen` equal to the sealed closure's minted
/// generation), the admission authority's custody binding (the held
/// pidfd bound to the admitted image), the sealed successful
/// attachment for the admitted domain, and the admitted image itself.
/// No caller-provided record/control structs on this path. Returns the native
/// evidence issuance token with the observed evidence; neither authorizes a
/// production grant without the validated H0 association. The seal pulls fresh
/// evidence again, so native truth that moved between the two refuses.
///
/// Live map reads stay UNRUN: production wires [`LiveBirthRows`];
/// host tests read fixture bytes the real native leaves published.
pub(crate) fn observe_exec_birth(
    rows: &mut impl BirthRowReader,
    binding: &crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding,
    attachment: &super::AttachedSemanticSet,
    admitted: &crate::discovery::caller_registry::instance_input::AdmittedInstanceCall,
) -> std::result::Result<
    (
        SessionGrantToken,
        crate::semantics_objects::journal::SessionBirthEvidence,
    ),
    BirthObservationRefusal,
> {
    use p11scope_ebpf_common::journal_marker::{MarkerRead, read_word};
    let record = rows
        .read_marker_row()
        .map_err(|_| BirthObservationRefusal::RowUnreadable)?;
    let control = rows
        .read_admission_control()
        .map_err(|_| BirthObservationRefusal::RowUnreadable)?;
    let (image, custody_word) = common_birth_words(&control, binding, attachment, admitted)?;
    match read_word(record.journal_bootstrap) {
        MarkerRead::Ready(exec) if exec == image.1 => {}
        _ => return Err(BirthObservationRefusal::MarkerNotReady),
    }
    // READY plus matching image/generation: the row's observed
    // exec_attach_gen must equal the sealed closure's minted
    // generation — an exec stamped under another closure (or never
    // stamped) is not this closure's birth. Checked after the marker
    // readback so a doubly-bad row reports its marker state first.
    if record.exec_attach_gen != attachment.generation() {
        return Err(BirthObservationRefusal::GenerationMismatch);
    }
    let token = SessionGrantToken(());
    let evidence = crate::semantics_objects::journal::SessionBirthEvidence::issue(
        &token,
        image,
        record.journal_bootstrap,
        control.failed,
        record.exec_attach_gen,
        custody_word,
    );
    Ok((token, evidence))
}

/// Session-owned absence-appearance birth observation: the shared
/// producers plus a committed negative witness followed by a
/// router-joined appearance at advanced epochs. The marker row reads
/// back unmarked (absence births never publish, so any publication
/// or poisoning refuses); the sealed provider-free interval names
/// this birth's process and ran after the sealed closure (its attach
/// cell equals the closure's minted generation); and the appearance
/// — same process, domain, and file, strictly advanced epochs past
/// the negative, a full accepted mapping — joins as a
/// router-accepted new observation. The positive stays withheld
/// until the negative commits: every negative check passes before
/// the appearance joins the router. No caller-provided
/// record/control structs on this path. Live map reads stay UNRUN:
/// production wires [`LiveBirthRows`] and live scans.
#[cfg(test)] // Legacy negative-protocol unit seam; production consumes actual H0 novelty.
pub(crate) fn observe_absence_birth(
    rows: &mut impl BirthRowReader,
    absence: crate::attach::image_query::ImageAbsenceProof,
    appearance: crate::attach::image_query::ImageScanProof,
    router: &mut crate::discovery::instances::InstanceRouter,
    binding: &crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding,
    attachment: &super::AttachedSemanticSet,
    admitted: &crate::discovery::caller_registry::instance_input::AdmittedInstanceCall,
) -> std::result::Result<
    (
        SessionGrantToken,
        crate::semantics_objects::journal::SessionBirthEvidence,
    ),
    BirthObservationRefusal,
> {
    let record = rows
        .read_marker_row()
        .map_err(|_| BirthObservationRefusal::RowUnreadable)?;
    let control = rows
        .read_admission_control()
        .map_err(|_| BirthObservationRefusal::RowUnreadable)?;
    let (image, custody_word) = common_birth_words(&control, binding, attachment, admitted)?;
    if record.journal_bootstrap != 0 {
        return Err(BirthObservationRefusal::MarkerPublished);
    }
    // The negative commits first: the sealed provider-free interval
    // scans the admitted process, and its attach cell is the sealed
    // closure's minted generation — the enumeration ran after this
    // closure's publication. A scan of another process, or one that
    // ran under another closure, is not this birth's witness.
    if absence.image().task_cookie != image.0 {
        return Err(BirthObservationRefusal::AppearanceForeign);
    }
    if absence.attach_generation() != attachment.generation() {
        return Err(BirthObservationRefusal::GenerationMismatch);
    }
    // Same birth's appearance: it continues the negative's process,
    // domain, and file. Anything else is not this birth's
    // appearance.
    if appearance.image().task_cookie != absence.image().task_cookie
        || appearance.domain() != absence.domain()
        || appearance.file_slot() != absence.file_slot()
    {
        return Err(BirthObservationRefusal::AppearanceForeign);
    }
    // Strictly advanced epochs past the negative: the un-journaled
    // exec the birth backfills. Unchanged counters are a
    // re-presentation, not an appearance.
    let before = absence.epochs();
    let after = appearance.epochs();
    if (after.local, after.global) <= (before.local, before.global) {
        return Err(BirthObservationRefusal::AppearanceNotAdvanced);
    }
    // N15: the negative's retained publication fence must be CURRENT
    // (the router's live fence, read here — never a cached value)
    // and CONSISTENT with the appearance before the positive
    // publishes. The router validates only the appearance it
    // receives, so without this an absence witness sealed before a
    // fault-era gap would bridge the gap beside a fresh appearance.
    // Outstanding negatives therefore never survive a gap/void
    // transition: any take after the fence moved refuses here, and
    // the single-shot take consumes the pair, so no later take can
    // recover bootstrap through ordinary S1 recovery (H8:117). The
    // positive stays withheld: this fires before the router join.
    if absence.fence() != router.fence() || appearance.fence() != absence.fence() {
        return Err(BirthObservationRefusal::NegativeFenceMismatch);
    }
    // The negative committed: the appearance must join as a
    // genuinely new observation. Anything else refuses.
    use crate::discovery::instances::ObserveOutcome;
    match router.observe(appearance).0 {
        ObserveOutcome::New => {}
        _ => return Err(BirthObservationRefusal::AppearanceRejected),
    }
    let token = SessionGrantToken(());
    let evidence = crate::semantics_objects::journal::SessionBirthEvidence::issue(
        &token,
        image,
        0,
        control.failed,
        absence.attach_generation(),
        custody_word,
    );
    Ok((token, evidence))
}

/// Production birth-row reader: live PROC_EPOCH and
/// JOURNAL_MARKER_CTL reads through the session's instance maps,
/// bound to the SAME custody the observation checks (constructed from
/// the binding itself — never a separately supplied fd). A
/// never-mutated process has no PROC_EPOCH row, which refuses (there
/// is no admission to read back) rather than reading as zero. UNRUN:
/// live map reads stay out of tests; the Session loop wires this when
/// the journal activates.
/// Custody gate for the production row reads: the SAME pin the
/// observation checks yields the pidfd the maps read through. A
/// pidfd-less (proc-fallback) pin refuses — rows are unreadable
/// without the original pidfd, and no substituted fd is ever read.
fn birth_rows_pidfd(
    pin: &crate::process::PidPin,
) -> std::result::Result<BorrowedFd<'_>, BirthRowError> {
    pin.pidfd().map_err(|_| BirthRowError::Unreadable)
}

#[allow(dead_code)] // No Session-loop wire until live activation; tests drive fixtures.
pub(crate) struct LiveBirthRows<'m> {
    maps: &'m InstanceMaps<'m>,
    pin: std::sync::Arc<crate::process::PidPin>,
}

#[allow(dead_code)] // As above.
impl<'m> LiveBirthRows<'m> {
    pub(crate) fn over(
        maps: &'m InstanceMaps<'m>,
        binding: &crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding,
    ) -> Self {
        Self {
            maps,
            pin: binding.pin(),
        }
    }
}

/// Missing-storage mapping for the production marker-row read (the
/// live reader pulls `record()` through this; UNRUN under live maps).
/// A missing row refuses: a process that never mutated a watched file
/// has no admission to read back (missing/busy/unreadable is not
/// clean zero) — the observation refuses instead of admitting a
/// fabricated default.
fn marker_row_or_refuse(
    row: Option<InstanceRecord>,
) -> std::result::Result<InstanceRecord, BirthRowError> {
    row.ok_or(BirthRowError::Unreadable)
}

/// Detailed-only birth marker control (`JOURNAL_MARKER_CTL[0]`):
/// exact metadata, zero readback, then freeze before any link. A
/// Detailed object without the map is a stale build; a counter
/// bank object with the map is refused without touching it.
/// UNRUN: live map access stays out of tests; the verdict below is
/// pinned over pure values.
pub(super) fn prepare_marker_control(ebpf: &aya::Ebpf, roots: StaticRoots) -> Result<()> {
    const NAME: &str = "JOURNAL_MARKER_CTL";
    let map = ebpf.map(NAME);
    if roots == StaticRoots::CounterBanks {
        return marker_control_verdict(map.is_some(), roots, None);
    }
    let Some(map) = map else {
        return marker_control_verdict(false, roots, None);
    };
    let data = super::policy_map_data(NAME, map)?;
    super::validate_map_metadata(NAME, data, super::map_metadata(MapType::Array, 4, 16, 1, 0))?;
    let control: Array<&MapData, JournalAdmissionControl> = Array::try_from(map)?;
    let readback = control
        .get(&0, 0)
        .with_context(|| format!("reading {NAME} control row"))?;
    marker_control_verdict(true, roots, Some(readback))?;
    super::freeze_map(NAME, map)
}

/// Pure control-row verdict behind [`prepare_marker_control`]: a
/// Detailed session needs the map with a zero readback (a missing
/// map is a stale build; a nonzero row moved before the freeze),
/// while counter banks must not carry the map at all.
fn marker_control_verdict(
    present: bool,
    roots: StaticRoots,
    readback: Option<JournalAdmissionControl>,
) -> Result<()> {
    match (roots, present) {
        (StaticRoots::CounterBanks, true) => {
            bail!("JOURNAL_MARKER_CTL present in a counter bank object")
        }
        (StaticRoots::CounterBanks, false) => Ok(()),
        (StaticRoots::Detailed, false) => {
            bail!("JOURNAL_MARKER_CTL missing from the Detailed object (stale build)")
        }
        (StaticRoots::Detailed, true) => match readback {
            Some(control) if control.spent == 0 && control.failed == 0 => Ok(()),
            Some(control) => bail!(
                "JOURNAL_MARKER_CTL moved before links: spent={} failed={}",
                control.spent,
                control.failed
            ),
            None => bail!("JOURNAL_MARKER_CTL has no readback row"),
        },
    }
}

#[allow(dead_code)] // As above.
impl BirthRowReader for LiveBirthRows<'_> {
    fn read_marker_row(&mut self) -> std::result::Result<InstanceRecord, BirthRowError> {
        let pidfd = birth_rows_pidfd(&self.pin)?;
        marker_row_or_refuse(
            self.maps
                .record(pidfd)
                .map_err(|_| BirthRowError::Unreadable)?,
        )
    }

    fn read_admission_control(
        &mut self,
    ) -> std::result::Result<p11scope_ebpf_common::JournalAdmissionControl, BirthRowError> {
        self.maps
            .journal_admission_control()
            .map_err(|_| BirthRowError::Unreadable)
    }
}

/// Production exec-marker birth source: each take re-runs the exec
/// observation through the injected reader against live native state.
/// The seal pulls this (never a reusable value); the spent issuance
/// token drops with the take (the grant was issued at attestation).
/// UNRUN: the Session loop wires the live reader when the journal
/// activates.
#[allow(dead_code)] // No Session-loop wire until live activation; tests drive fixtures.
pub(crate) struct ExecBirthSource<'a, R> {
    rows: R,
    binding: &'a crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding,
    attachment: &'a super::AttachedSemanticSet,
    admitted: &'a crate::discovery::caller_registry::instance_input::AdmittedInstanceCall,
}

#[allow(dead_code)] // As above.
impl<'a, R: BirthRowReader> ExecBirthSource<'a, R> {
    pub(crate) fn over(
        rows: R,
        binding: &'a crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding,
        attachment: &'a super::AttachedSemanticSet,
        admitted: &'a crate::discovery::caller_registry::instance_input::AdmittedInstanceCall,
    ) -> Self {
        Self {
            rows,
            binding,
            attachment,
            admitted,
        }
    }
}

#[allow(dead_code)] // As above.
impl<R: BirthRowReader> crate::semantics_objects::journal::BirthEvidenceSource
    for ExecBirthSource<'_, R>
{
    fn take_birth_evidence(
        &mut self,
    ) -> std::result::Result<
        crate::semantics_objects::journal::SessionBirthEvidence,
        BirthObservationRefusal,
    > {
        observe_exec_birth(&mut self.rows, self.binding, self.attachment, self.admitted)
            .map(|(_token, evidence)| evidence)
    }
}

/// Production absence-appearance birth source: each take re-runs the
/// absence observation (committed negative witness, advanced-epoch
/// appearance) against live native state. UNRUN: the Session loop
/// wires live scans when the journal activates.
#[allow(dead_code)] // No Session-loop wire until live activation; tests drive fixtures.
#[cfg(test)]
pub(crate) struct AbsenceBirthSource<'a, R> {
    rows: R,
    absence: Option<crate::attach::image_query::ImageAbsenceProof>,
    appearance: Option<crate::attach::image_query::ImageScanProof>,
    router: &'a mut crate::discovery::instances::InstanceRouter,
    binding: &'a crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding,
    attachment: &'a super::AttachedSemanticSet,
    admitted: &'a crate::discovery::caller_registry::instance_input::AdmittedInstanceCall,
}

#[allow(dead_code)] // As above.
#[cfg(test)]
impl<'a, R: BirthRowReader> AbsenceBirthSource<'a, R> {
    /// Wire one absence birth: live rows, the sealed negative
    /// witness, the appearance, and the real router the appearance
    /// must join. (Too many arguments is the honest shape: every
    /// producer is injected, none supplied.)
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn over(
        rows: R,
        absence: crate::attach::image_query::ImageAbsenceProof,
        appearance: crate::attach::image_query::ImageScanProof,
        router: &'a mut crate::discovery::instances::InstanceRouter,
        binding: &'a crate::discovery::engine::inventory_coordinator::semantics::SemanticCallerBinding,
        attachment: &'a super::AttachedSemanticSet,
        admitted: &'a crate::discovery::caller_registry::instance_input::AdmittedInstanceCall,
    ) -> Self {
        Self {
            rows,
            absence: Some(absence),
            appearance: Some(appearance),
            router,
            binding,
            attachment,
            admitted,
        }
    }
}

#[allow(dead_code)] // As above.
#[cfg(test)]
impl<R: BirthRowReader> crate::semantics_objects::journal::BirthEvidenceSource
    for AbsenceBirthSource<'_, R>
{
    fn take_birth_evidence(
        &mut self,
    ) -> std::result::Result<
        crate::semantics_objects::journal::SessionBirthEvidence,
        BirthObservationRefusal,
    > {
        // The witness pair is single-shot: the first take consumes
        // the source's scans, so a reused appearance cannot birth
        // twice. (A second take would need a fresh acquisition; the
        // seal pulls exactly one birth per grant.) Takes after the
        // first fail closed on the consumed scans.
        let absence = self
            .absence
            .take()
            .ok_or(BirthObservationRefusal::AppearanceRejected)?;
        let appearance = self
            .appearance
            .take()
            .ok_or(BirthObservationRefusal::AppearanceRejected)?;
        observe_absence_birth(
            &mut self.rows,
            absence,
            appearance,
            self.router,
            self.binding,
            self.attachment,
            self.admitted,
        )
        .map(|(_token, evidence)| evidence)
    }
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

    /// The live attach cell (`INSTANCE_GEN[GEN_ATTACH]`): the closure
    /// generation native stamps exec'ing records from. The absence
    /// seal reads it inside its brackets; the observer compares it to
    /// the claimed closure. UNRUN: live map access stays out of tests.
    pub(crate) fn attach_cell(&self) -> Result<u64> {
        self.array_u64("INSTANCE_GEN", instance::GEN_ATTACH)
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
    /// watched file (callers refuse absence; it is not a zero admission).
    pub(crate) fn record(&self, pidfd: BorrowedFd<'_>) -> Result<Option<InstanceRecord>> {
        task_storage_lookup(self.ebpf, "PROC_EPOCH", pidfd)
    }

    /// The Detailed-only admission control row (`JOURNAL_MARKER_CTL[0]`):
    /// spent permits plus the failed latch. Userspace never writes it.
    /// Live read (UNRUN); the birth observation pulls it through the
    /// birth-row reader.
    pub(crate) fn journal_admission_control(
        &self,
    ) -> Result<p11scope_ebpf_common::JournalAdmissionControl> {
        let map: Array<&MapData, p11scope_ebpf_common::JournalAdmissionControl> = Array::try_from(
            self.ebpf
                .map("JOURNAL_MARKER_CTL")
                .context("JOURNAL_MARKER_CTL map")?,
        )?;
        Ok(map.get(&0, 0)?)
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

    /// Mints one closure generation from the mmapable attach cell: the
    /// production mint behind Session sealing (BPF stamps exec'ing
    /// records from this cell as `exec_attach_gen`). UNRUN: live map
    /// access stays out of tests; the CAS core and the mmapable
    /// wrapper are pinned over local atomics and file-backed pages.
    pub(crate) fn mint_attach_generation(&self) -> Result<u64> {
        let data = match self.ebpf.map("INSTANCE_GEN").context("INSTANCE_GEN map")? {
            aya::maps::Map::Array(data) => data,
            other => bail!("unexpected INSTANCE_GEN variant {other:?}"),
        };
        fetch_add_mmapped_attach(data.fd().as_fd())
    }

    /// Full cells from this object's original pidfd and watched file. The
    /// owner brackets these reads with same-domain image/health checks.
    pub(crate) fn complete_epochs(
        &self,
        pidfd: BorrowedFd<'_>,
        file: u32,
    ) -> Result<super::image_query::CompleteEpochs> {
        ensure!(file < instance::FILE_SLOTS, "invalid watched file slot");
        let (local, record_flags) = self.record(pidfd)?.map_or((0, 0), |record| {
            (
                record
                    .slot_plus1
                    .iter()
                    .position(|slot| *slot == u64::from(file) + 1)
                    .map_or(0, |index| record.epoch[index]),
                record.flags,
            )
        });
        Ok(super::image_query::CompleteEpochs {
            local,
            record_flags,
            global: self.global(file)?,
            fault: self.fault()?,
            sticky: self.sticky()?,
        })
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

pub(super) fn raise_fault_cell(cell: &std::sync::atomic::AtomicU64) -> Result<u64> {
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

/// Bounded checked fetch-add on the mmapable attach cell: production
/// closure mints from native (the cell BPF stamps into exec'ing
/// records as `exec_attach_gen`), never the interim userspace
/// counter. Returns the minted generation (1, 2, ... from zero).
pub(super) fn mint_attach_cell(cell: &std::sync::atomic::AtomicU64) -> Result<u64> {
    use std::sync::atomic::Ordering;
    let mut seen = cell.load(Ordering::SeqCst);
    for _ in 0..8 {
        let next = seen.checked_add(1).context("attach generation exhausted")?;
        match cell.compare_exchange(seen, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return Ok(next),
            Err(current) => seen = current,
        }
    }
    bail!("attach generation contention")
}

/// Mint one closure generation through the mmapable attach cell: the
/// production mint behind [`InstanceMaps::mint_attach_generation`].
/// Userspace is the cell's sole writer (native only stamps FROM it at
/// exec), so the bounded CAS cannot lose to a native writer.
fn fetch_add_mmapped_attach(fd: BorrowedFd<'_>) -> Result<u64> {
    use p11scope_ebpf_common::instance::GEN_ATTACH;
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
    // SAFETY: the attach cell is an aligned u64 inside the mapped page.
    let cell = unsafe {
        &*((address as *const u8).add(usize::try_from(GEN_ATTACH).expect("attach cell index") * 8)
            as *const std::sync::atomic::AtomicU64)
    };
    let minted = mint_attach_cell(cell);
    // SAFETY: exactly the mapping created above.
    unsafe { libc::munmap(address, 4096) };
    minted
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

    #[test]
    fn missing_marker_storage_refuses_instead_of_defaulting() {
        // N11: a missing marker row has no admission to read back
        // (missing/busy/unreadable is not clean zero) — the
        // production reader refuses it; a present row passes through.
        assert!(matches!(
            super::marker_row_or_refuse(None),
            Err(super::BirthRowError::Unreadable)
        ));
        let row = p11scope_ebpf_common::InstanceRecord {
            slot_plus1: [1, 0, 0, 0, 0, 0, 0, 0],
            epoch: [0; 8],
            flags: 0,
            exec_attach_gen: 0,
            journal_bootstrap: 0,
        };
        let back = super::marker_row_or_refuse(Some(row)).expect("present row passes");
        assert_eq!(back.slot_plus1[0], 1);
        assert_eq!(back.exec_attach_gen, 0);
    }

    #[test]
    fn attach_mint_is_native_monotonic_and_exact() {
        // C1: production closure mints from the mmapable attach cell
        // (the cell BPF stamps into exec records), never the interim
        // userspace counter. The CAS core mints 1, 2, ... from zero
        // and never invents a generation under contention. Eight failed CAS
        // attempts may refuse; a caller must not assume every mint succeeds.
        use std::sync::atomic::{AtomicU64, Ordering};
        let cell = AtomicU64::new(0);
        assert_eq!(super::mint_attach_cell(&cell).unwrap(), 1);
        assert_eq!(super::mint_attach_cell(&cell).unwrap(), 2);
        assert_eq!(cell.load(Ordering::SeqCst), 2);
        let exhausted = AtomicU64::new(u64::MAX - 1);
        assert_eq!(super::mint_attach_cell(&exhausted).unwrap(), u64::MAX);
        for _ in 0..2 {
            assert_eq!(
                super::mint_attach_cell(&exhausted).unwrap_err().to_string(),
                "attach generation exhausted"
            );
            assert_eq!(exhausted.load(Ordering::SeqCst), u64::MAX);
        }
        let cell = std::sync::Arc::new(AtomicU64::new(0));
        let start = std::sync::Arc::new(std::sync::Barrier::new(4));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let shared = cell.clone();
            let start = start.clone();
            handles.push(std::thread::spawn(move || {
                let mut minted = Vec::new();
                let mut refused = 0;
                start.wait();
                for _ in 0..250 {
                    match super::mint_attach_cell(&shared) {
                        Ok(generation) => minted.push(generation),
                        Err(error) => {
                            assert_eq!(error.to_string(), "attach generation contention");
                            refused += 1;
                        }
                    }
                }
                assert!(minted.windows(2).all(|pair| pair[0] < pair[1]));
                (minted, refused)
            }));
        }
        let mut all = Vec::new();
        let mut refused = 0;
        for handle in handles {
            let (minted, refusals) = handle.join().unwrap();
            all.extend(minted);
            refused += refusals;
        }
        assert!(!all.is_empty());
        assert_eq!(all.len() + refused, 1000);
        all.sort_unstable();
        assert_eq!(all, (1..=all.len() as u64).collect::<Vec<_>>());
        assert_eq!(cell.load(Ordering::SeqCst), all.len() as u64);
    }

    #[test]
    fn attach_mint_maps_the_mmapable_cell() {
        // C1: the mmapable wrapper mints through a shared mapping at
        // the attach cell (a file-backed page stands in for the BPF
        // array; only the fd source is live-only).
        use std::os::fd::AsFd;
        let file = tempfile::tempfile().unwrap();
        file.set_len(4096).unwrap();
        let first = super::fetch_add_mmapped_attach(file.as_fd()).unwrap();
        let second = super::fetch_add_mmapped_attach(file.as_fd()).unwrap();
        assert_eq!((first, second), (1, 2));
    }

    #[test]
    fn birth_row_reads_share_the_checked_custody() {
        // C1: the production row source reads through the SAME pin the
        // observation checks — a live pin yields its pidfd, while a
        // pidfd-less (proc-fallback) pin refuses instead of reading
        // through any substituted fd.
        let live = crate::process::PidPin::open(std::process::id()).unwrap();
        assert!(super::birth_rows_pidfd(&live).is_ok());
        let fallback = crate::process::PidPin::test_proc_only(std::process::id());
        assert!(matches!(
            super::birth_rows_pidfd(&fallback),
            Err(super::BirthRowError::Unreadable)
        ));
    }

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

    fn exec_release_btf_fixture(header_len: u32, string_gap: usize) -> Vec<u8> {
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
            header_len,
            0,
            types.len() as u32,
            types.len() as u32 + string_gap as u32,
            strings.len() as u32,
        ] {
            bytes.extend(word.to_le_bytes());
        }
        bytes.resize(header_len as usize, 0xa5);
        bytes.extend(types);
        bytes.resize(bytes.len() + string_gap, 0x5a);
        bytes.extend(strings);
        bytes
    }

    #[test]
    fn image_hook_requires_the_exact_exec_release_prototype() {
        let bytes = exec_release_btf_fixture(24, 0);
        assert!(exec_release_proto_is_exact(&bytes));
        let mut wrong = bytes.clone();
        wrong[24 + 48 + 16..24 + 48 + 20].copy_from_slice(&4u32.to_le_bytes());
        assert!(!exec_release_proto_is_exact(&wrong));
        for truncated in 0..bytes.len() {
            assert!(!exec_release_proto_is_exact(&bytes[..truncated]));
        }
    }

    #[test]
    fn image_hook_preflight_uses_original_cached_bytes_and_rejects_foreign_parse() {
        use super::super::host_btf;
        for (header, gap) in [(24, 0), (32, 0), (24, 7), (32, 7)] {
            let bytes = exec_release_btf_fixture(header, gap);
            let foreign = aya::Btf::parse(&bytes, aya::Endianness::default()).unwrap();
            assert!(exec_release_proto_is_exact(&bytes));
            assert_eq!(
                exec_release_proto_is_exact(&foreign.to_bytes()),
                header == 24 && gap == 0,
                "pinned Aya does not retain the header extension or string gap"
            );
            let cell = std::sync::OnceLock::new();
            let host = host_btf::cached(&cell, || Ok(bytes)).unwrap();
            super::validate_exec_release_proto(host, host.btf()).unwrap();
            assert_eq!(
                super::validate_exec_release_proto(host, &foreign)
                    .unwrap_err()
                    .to_string(),
                "instance hook BTF differs from cached host BTF"
            );
        }
    }

    #[test]
    fn image_hook_cached_preflight_keeps_signature_and_extent_refusals() {
        use super::super::host_btf;
        let signature_refuses = |bytes| {
            let cell = std::sync::OnceLock::new();
            let host = host_btf::cached(&cell, || Ok(bytes))
                .expect("signature mutant must remain parseable BTF");
            assert_eq!(
                super::validate_exec_release_proto(host, host.btf())
                    .unwrap_err()
                    .to_string(),
                "exec_mm_release must be void(task_struct *, mm_struct *)"
            );
        };
        let check = |bytes| {
            let cell = std::sync::OnceLock::new();
            match host_btf::cached(&cell, || Ok(bytes)) {
                Ok(host) => super::validate_exec_release_proto(host, host.btf()).is_ok(),
                Err(_) => false,
            }
        };
        for (header, gap) in [(24, 0), (32, 7)] {
            let bytes = exec_release_btf_fixture(header, gap);
            assert!(check(bytes.clone()));
            let proto = header as usize + 48;
            let mut wrong_return = bytes.clone();
            wrong_return[proto + 8..proto + 12].copy_from_slice(&1u32.to_le_bytes());
            signature_refuses(wrong_return);
            let mut wrong_argument = bytes.clone();
            wrong_argument[proto + 16..proto + 20].copy_from_slice(&4u32.to_le_bytes());
            signature_refuses(wrong_argument);
            let type_len = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
            let type_end = header as usize + type_len as usize;
            let mut duplicate = bytes.clone();
            duplicate.splice(
                type_end..type_end,
                bytes[type_end - 12..type_end].iter().copied(),
            );
            duplicate[12..16].copy_from_slice(&(type_len + 12).to_le_bytes());
            duplicate[16..20].copy_from_slice(&(type_len + gap as u32 + 12).to_le_bytes());
            signature_refuses(duplicate);
            for truncated in 0..bytes.len() {
                assert!(
                    !check(bytes[..truncated].to_vec()),
                    "truncated at {truncated}"
                );
            }
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
    fn marker_control_detailed_zero_readback_accepts() {
        // H8-D: a Detailed session starts only over a zeroed
        // control row; the freeze then seals it before any link.
        let control = p11scope_ebpf_common::JournalAdmissionControl {
            spent: 0,
            failed: 0,
        };
        super::marker_control_verdict(true, super::StaticRoots::Detailed, Some(control))
            .expect("zero readback accepts");
    }

    #[test]
    fn marker_control_detailed_spent_readback_refuses() {
        // H8-D: a spent permit before links means the control
        // moved early; the session refuses instead of starting.
        let control = p11scope_ebpf_common::JournalAdmissionControl {
            spent: 1,
            failed: 0,
        };
        assert!(
            super::marker_control_verdict(true, super::StaticRoots::Detailed, Some(control))
                .is_err()
        );
    }

    #[test]
    fn marker_control_detailed_latched_readback_refuses() {
        // H8-D: a tripped latch before links refuses the session.
        let control = p11scope_ebpf_common::JournalAdmissionControl {
            spent: 0,
            failed: 1,
        };
        assert!(
            super::marker_control_verdict(true, super::StaticRoots::Detailed, Some(control))
                .is_err()
        );
    }

    #[test]
    fn marker_control_detailed_absent_map_refuses() {
        // H8-D: a Detailed object without the map is a stale
        // build; the session refuses instead of running blind.
        assert!(super::marker_control_verdict(false, super::StaticRoots::Detailed, None).is_err());
    }

    #[test]
    fn marker_control_counter_present_refuses() {
        // H8-D: counter bank objects must not carry the marker
        // map; a session over one refuses.
        assert!(
            super::marker_control_verdict(true, super::StaticRoots::CounterBanks, None).is_err()
        );
    }

    #[test]
    fn marker_control_counter_absent_accepts() {
        // H8-D: the healthy counter twin of the refusal above.
        super::marker_control_verdict(false, super::StaticRoots::CounterBanks, None)
            .expect("counter banks without the map accept");
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

    #[test]
    fn pre_68_overlay_maps_select_through_the_calibration_key() {
        use p11scope_ebpf_common::InstanceFileKey;
        use p11scope_manifest::maps::{Device, ObjectKey};

        // A 6.6 guest maps snapshot for a provider on the virtme /tmp
        // overlay: maps shows the backing (upper tmpfs) device 0x19 = 25,
        // while the mountinfo-derived raw key carries the overlay
        // superblock 0:48. Both name inode 802 (`xino=off`).
        let snapshot = b"771234560000-771234561000 r--p 00000000 00:19 802 /tmp/provider.so\n\
            771234561000-771234571000 r-xp 00001000 00:19 802 /tmp/provider.so\n\
            00400000-00401000 r-xp 00000000 08:01 111 /usr/bin/driver\n";
        let entries = p11scope_manifest::maps::parse_maps(snapshot).expect("fixture parses");
        assert_eq!(entries.len(), 3);
        let raw = ObjectKey {
            device: Device {
                major: 0,
                minor: 48,
            },
            inode: 802,
        };
        // The raw key alone selects nothing on pre-6.8 overlay maps.
        assert!(
            crate::discovery::instances::ranges_for(
                &entries,
                raw.device.major,
                raw.device.minor,
                raw.inode
            )
            .is_empty()
        );
        // The watch keeps the raw key (6.8+ kernels show it) and adds the
        // calibration kernel key (pre-6.8 kernels show it).
        let keys = super::maps_keys_for_watch(vec![raw], InstanceFileKey { dev: 25, ino: 802 });
        assert!(keys.contains(&raw));
        let selected: Vec<_> = keys
            .iter()
            .flat_map(|key| {
                crate::discovery::instances::ranges_for(
                    &entries,
                    key.device.major,
                    key.device.minor,
                    key.inode,
                )
            })
            .collect();
        assert_eq!(selected.len(), 2);
    }

    #[test]
    fn calibration_key_uses_kernel_kdev_t_decoding() {
        use p11scope_ebpf_common::InstanceFileKey;
        use p11scope_manifest::maps::{Device, ObjectKey};

        // An ext4 provider on 8:1: the hook reports the raw `s_dev`
        // (8 << 20) | 1, and maps shows 08:01. Userspace `st_dev`
        // decoding (`libc::major`/`libc::minor`) would misread this as
        // major 0; kernel MAJOR/MINOR must be used, so the calibration
        // key dedupes against the identical raw key.
        let raw = ObjectKey {
            device: Device { major: 8, minor: 1 },
            inode: 99,
        };
        assert_eq!(
            super::maps_keys_for_watch(
                vec![raw],
                InstanceFileKey {
                    dev: (8 << 20) | 1,
                    ino: 99
                }
            ),
            vec![raw]
        );
        // An unnamed device with a minor above 255 decodes to (0, 300),
        // never the userspace-st_dev reading (1, 44).
        assert_eq!(
            super::maps_keys_for_watch(Vec::new(), InstanceFileKey { dev: 300, ino: 7 }),
            vec![ObjectKey {
                device: Device {
                    major: 0,
                    minor: 300
                },
                inode: 7
            }]
        );
        // A major above 255 (NVMe-style 259:7) needs the 12-bit major
        // field; userspace `st_dev` decoding would read this as (0, 66311).
        assert_eq!(
            super::maps_keys_for_watch(
                Vec::new(),
                InstanceFileKey {
                    dev: (259 << 20) | 7,
                    ino: 5
                }
            ),
            vec![ObjectKey {
                device: Device {
                    major: 259,
                    minor: 7
                },
                inode: 5
            }]
        );
    }

    #[test]
    fn watched_file_constructor_keeps_raw_and_calibration_keys() {
        use crate::discovery::identity::test_fixture::real_scan_pin;
        use p11scope_ebpf_common::InstanceFileKey;
        use p11scope_manifest::maps::{Device, ObjectKey};
        use std::os::unix::fs::MetadataExt as _;

        // `watch()` builds every `WatchedFile` through `for_watch` (the
        // only production construction site), so this pins the
        // key-joining rule where the helper tests cannot: a later edit
        // that drops the calibration key from the constructor fails
        // here on every kernel, while on 6.8+ hosts even the live
        // cells would stay green without it.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("provider");
        std::fs::write(&path, b"provider bytes").unwrap();
        let pins = real_scan_pin(&path, None, 1, "constructor-digest");
        let object = pins.pinned().next().unwrap().id;
        let raw = pins.raw_keys_for(object);
        assert!(!raw.is_empty());
        let metadata = std::fs::metadata(&path).unwrap();
        // The probed 6.6 backing pair (52, 11): no raw key of this
        // pinned temp file may already name it, or the added-key
        // assertion below would pass vacuously.
        let added = ObjectKey {
            device: Device {
                major: 0,
                minor: 52,
            },
            inode: 11,
        };
        assert!(
            !raw.contains(&added),
            "test environment collides with the (52, 11) probe vector: {raw:?}"
        );
        let watched = super::WatchedFile::for_watch(
            3,
            raw.clone(),
            InstanceFileKey { dev: 52, ino: 11 },
            crate::discovery::instances::MappedFileIdentity {
                dev: metadata.dev(),
                ino: metadata.ino(),
            },
            pins.retain_inventory_target(object).unwrap(),
        );
        assert_eq!(watched.file_slot, 3);
        for key in &raw {
            assert!(watched.maps_keys.contains(key), "raw key lost: {key:?}");
        }
        assert!(watched.maps_keys.contains(&added));
        assert_eq!(watched.identity.dev, metadata.dev());
        assert_eq!(watched.identity.ino, metadata.ino());
    }
}
