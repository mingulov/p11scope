//! SPDX-License-Identifier: GPL-3.0-or-later
//! SPDX-FileCopyrightText: 2026 Denis Mingulov <denis@mingulov.com>
//! Task 3 Stage A: the Session side of the load-instance continuity witness.
//!
//! - Loads the four native continuity hooks (`uprobe_mmap`, `uprobe_munmap`,
//!   `copy_vma` (fixed-slot through the 5-argument shape, `bpf_get_func_ret`
//!   on the 6/7-argument shapes), and the exec-release hook:
//!   `exec_mm_release` through 7.2, `exec_mmap` from 7.3) before deferred
//!   policy freezes, and attaches
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
const EXIT_PROGRAMS: [&str; 3] = [
    "p11_inst_vma_copy",
    COPY_VMA_RET_PROGRAM,
    EXEC_RELEASE_MMAP_PROGRAM,
];

/// The 7.3+ exec-release hook program and its kernel attach target. Kernels
/// through 7.2 carry `exec_mm_release`; 7.3 removed it, merging exit and exec
/// release into `mm_exit_exec_release`. That merged function also fires on
/// thread exit, where poisoning live continuity would be wrong, so newer
/// kernels hook the success-gated `exec_mmap` exit instead.
pub(crate) const EXEC_RELEASE_MMAP_PROGRAM: &str = "p11_image_mmap_release";
const EXEC_RELEASE_MMAP_TARGET: &str = "exec_mmap";

/// Which kernel hook carries exec-release invalidation on this host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecReleaseTarget {
    ExecMmRelease,
    ExecMmap,
}

/// The 6/7-argument `copy_vma` hook program. Kernels through the 5-argument
/// shape keep `p11_inst_vma_copy`, which reads the returned new VMA from
/// the fixed fexit slot; newer kernels (stable backports of 838bb60dc215,
/// 7.3+) pass more arguments, so the return slot moves and the hook reads
/// it through `bpf_get_func_ret` instead.
pub(crate) const COPY_VMA_RET_PROGRAM: &str = "p11_inst_vma_retcopy";

/// Which `copy_vma` prototype the host kernel carries: the 5-argument
/// legacy shape or the 6/7-argument extended shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CopyVmaTarget {
    Legacy,
    FuncRet,
}

/// The resolved kernel hook set: one `copy_vma` slot, one exec-release slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HookTargets {
    pub(crate) copy: CopyVmaTarget,
    pub(crate) exec: ExecReleaseTarget,
}

/// The four instance-hook (program, target) triples for resolved targets.
/// The legacy set is [`INSTANCE_PROGRAMS`]; each variant slot swaps only
/// its own program, so four sets exist (two slots of two).
pub(crate) fn active_instance_programs(targets: HookTargets) -> [(&'static str, &'static str); 4] {
    let copy = match targets.copy {
        CopyVmaTarget::Legacy => INSTANCE_PROGRAMS[2],
        CopyVmaTarget::FuncRet => (COPY_VMA_RET_PROGRAM, "copy_vma"),
    };
    let exec = match targets.exec {
        ExecReleaseTarget::ExecMmRelease => INSTANCE_PROGRAMS[3],
        ExecReleaseTarget::ExecMmap => (EXEC_RELEASE_MMAP_PROGRAM, EXEC_RELEASE_MMAP_TARGET),
    };
    [INSTANCE_PROGRAMS[0], INSTANCE_PROGRAMS[1], copy, exec]
}

/// Resolve the exec-release hook from the host BTF: the exact legacy
/// prototype wins when present, keeping older kernels byte-identical;
/// otherwise the exact exec_mmap shape selects the 7.3+ hook. Kernels
/// with neither refuse with the legacy message.
fn resolve_exec_release_target(
    host: &super::host_btf::HostBtf,
    btf: &Btf,
) -> Result<ExecReleaseTarget> {
    let raw = host
        .original_bytes_for(btf)
        .context("instance hook BTF differs from cached host BTF")?;
    if exec_release_proto_is_exact(raw) {
        return Ok(ExecReleaseTarget::ExecMmRelease);
    }
    if exec_mmap_proto_is_exact(raw) {
        return Ok(ExecReleaseTarget::ExecMmap);
    }
    validate_exec_release_proto(host, btf)?;
    bail!(
        "no exact exec-release hook: exec_mm_release must be void(task_struct *, mm_struct *) or exec_mmap must be int(linux_binprm *)"
    );
}

/// Resolve the `copy_vma` hook from the host BTF: the exact 5-argument
/// legacy prototype keeps the fixed-slot program; the exact 6/7-argument
/// extended shapes select the `bpf_get_func_ret` program. Anything else
/// refuses with the named shapes.
fn resolve_copy_vma_target(host: &super::host_btf::HostBtf, btf: &Btf) -> Result<CopyVmaTarget> {
    let raw = host
        .original_bytes_for(btf)
        .context("instance hook BTF differs from cached host BTF")?;
    if let Some(kind) = copy_vma_proto_kind(raw) {
        return Ok(kind);
    }
    validate_copy_vma_proto(host, btf)?;
    bail!(
        "no exact copy_vma hook: copy_vma must be struct vm_area_struct *(vmap, addr, len, pgoff[, anon_pgoff], need_rmap_locks[, keep_source])"
    );
}

/// Only the loader constructs this token. It stays inside one Session's
/// preparation/activation path and is consumed by attachment.
struct LoadedInstancePrograms {
    program_ids: BTreeMap<&'static str, u32>,
    targets: HookTargets,
}

fn load_instance_programs_with<S>(
    state: &mut S,
    targets: HookTargets,
    mut load: impl FnMut(&mut S, &'static str, &'static str) -> Result<u32>,
) -> Result<LoadedInstancePrograms> {
    let mut program_ids = BTreeMap::new();
    for (program, hook_target) in active_instance_programs(targets) {
        let id = load(state, program, hook_target)?;
        ensure!(
            id != 0 && !program_ids.values().any(|existing| *existing == id),
            "loaded image hook program IDs unavailable or collide"
        );
        program_ids.insert(program, id);
    }
    Ok(LoadedInstancePrograms {
        program_ids,
        targets,
    })
}

fn attach_loaded_instance_programs_with<S>(
    loaded: LoadedInstancePrograms,
    state: &mut S,
    mut attach: impl FnMut(&mut S, &'static str, &'static str) -> Result<()>,
) -> Result<()> {
    for (program, target) in active_instance_programs(loaded.targets) {
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
}

/// Records a prepare refusal. Coverage is intentionally untouched: the
/// hooks never started, so continuity is never-active (disabled), not
/// failed. Only a mid-run failure (audit, BPF image fault) or teardown
/// fails coverage. The BPF join gate consults exactly this distinction,
/// so refused-before-start systems never count unstamped returns as
/// unmatched. Takes coverage so the twin pins the no-fail contract.
fn apply_prepare_refusal(
    _coverage: &super::image_query::CoverageControl,
    tracking: &mut InstanceTracking,
    reason: String,
) {
    tracking.refused = Some(reason);
}

/// One watched provider file.
#[derive(Debug)]
pub(crate) struct WatchedFile {
    pub(crate) file_slot: u32,
    /// The keys this pinned object is known under in `/proc/PID/maps`;
    /// the scan selects the file's ranges by these. The pin's raw keys
    /// are maps-visible on every kernel; the appended calibration key
    /// is maps-visible only before 6.8 (from then on maps renders the
    /// user-visible overlay identity instead).
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
    /// The resolved hook targets; `None` until hooks attach.
    active_targets: Option<HookTargets>,
    links: Vec<(&'static str, HookLink)>,
    watched: BTreeMap<PinnedObjectId, Result<WatchedFile, String>>,
    keys: BTreeMap<InstanceFileKey, u32>,
    next_slot: u32,
    program_ids: BTreeMap<&'static str, u32>,
    /// Each hook's recursion-miss count at the last audit (zero before
    /// the first): growth raises the fault era, see
    /// [`audit_image_hooks_with`].
    hook_misses: std::sync::Mutex<BTreeMap<&'static str, u64>>,
    /// Fault raises made for recursion-miss growth (counts only).
    miss_raises: std::sync::atomic::AtomicU64,
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
pub(super) fn lto_enabled_in_config(config: &str) -> bool {
    config.lines().any(|line| {
        let line = line.trim();
        line.starts_with("CONFIG_LTO") && line != "CONFIG_LTO_NONE=y" && line.ends_with("=y")
    })
}

/// Decode one `/proc/config.gz` payload (IKCONFIG_PROC): the kernel's own
/// config for the RUNNING kernel, gzip-compressed. Bounded (4 MiB in,
/// 8 MiB out); anything larger, non-gzip or undecodable is an error and
/// the caller falls through to the next source, never assuming LTO-off.
fn decode_proc_config_gz(bytes: &[u8]) -> Result<String, String> {
    use std::io::Read as _;
    const MAX_COMPRESSED: usize = 4 * 1024 * 1024;
    const MAX_DECOMPRESSED: u64 = 8 * 1024 * 1024;
    if bytes.len() > MAX_COMPRESSED {
        return Err(format!(
            "compressed config exceeds {} bytes",
            MAX_COMPRESSED
        ));
    }
    if bytes.len() < 2 || bytes[0] != 0x1f || bytes[1] != 0x8b {
        return Err("not a gzip stream (bad magic)".to_string());
    }
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut text = String::new();
    decoder
        .take(MAX_DECOMPRESSED + 1)
        .read_to_string(&mut text)
        .map_err(|error| format!("gzip decode failed: {error}"))?;
    if text.len() as u64 > MAX_DECOMPRESSED {
        return Err(format!(
            "decompressed config exceeds {MAX_DECOMPRESSED} bytes"
        ));
    }
    Ok(text)
}

/// Whether the `/lib/modules/{release}/build` tree provably names the
/// RUNNING release: either `include/config/kernel.release` trims to it or
/// `include/generated/utsrelease.h` defines exactly it. A missing or
/// mismatched proof means the tree's `.config` is untrusted for this
/// kernel and must not decide in either direction.
fn modules_build_matches_release(
    release: &str,
    kernel_release_path: &Path,
    utsrelease_path: &Path,
) -> bool {
    if let Ok(stamped) = std::fs::read_to_string(kernel_release_path)
        && stamped.trim() == release
    {
        return true;
    }
    if let Ok(header) = std::fs::read_to_string(utsrelease_path) {
        for line in header.lines() {
            if let Some(rest) = line.trim().strip_prefix("#define UTS_RELEASE") {
                let rest = rest.trim();
                if rest.len() >= 2
                    && rest.starts_with('"')
                    && rest.ends_with('"')
                    && &rest[1..rest.len() - 1] == release
                {
                    return true;
                }
            }
        }
    }
    false
}

/// Ordered LTO verdict for one release over explicit paths (the test seam;
/// production passes the RUNNING release's real paths). First verifiable
/// source in order decides: `/boot/config-{release}`, `/proc/config.gz`,
/// then the modules `.config` only with a release proof. Nothing
/// verifiable refuses with every attempt named; LTO-off is never assumed.
fn lto_refusal_for_release(
    release: &str,
    boot_path: &Path,
    proc_gz_path: &Path,
    modules_config_path: &Path,
    kernel_release_path: &Path,
    utsrelease_path: &Path,
) -> Option<String> {
    let mut failures = Vec::new();
    match std::fs::read_to_string(boot_path) {
        Ok(config) => {
            if lto_enabled_in_config(&config) {
                return Some(format!(
                    "instance continuity hooks refused: LTO kernel ({} enables CONFIG_LTO_*; inlined hook-target copies escape fentry)",
                    boot_path.display()
                ));
            }
            return None;
        }
        Err(error) => failures.push(format!("{}: {error}", boot_path.display())),
    }
    match std::fs::read(proc_gz_path) {
        Ok(bytes) => match decode_proc_config_gz(&bytes) {
            Ok(config) => {
                if lto_enabled_in_config(&config) {
                    return Some(format!(
                        "instance continuity hooks refused: LTO kernel ({} enables CONFIG_LTO_*; inlined hook-target copies escape fentry)",
                        proc_gz_path.display()
                    ));
                }
                return None;
            }
            Err(error) => failures.push(format!("{}: {error}", proc_gz_path.display())),
        },
        Err(error) => failures.push(format!("{}: {error}", proc_gz_path.display())),
    }
    if !modules_build_matches_release(release, kernel_release_path, utsrelease_path) {
        failures.push(format!(
            "{}: build does not provably match running release {release}",
            modules_config_path.display()
        ));
    } else {
        match std::fs::read_to_string(modules_config_path) {
            Ok(config) => {
                if lto_enabled_in_config(&config) {
                    return Some(format!(
                        "instance continuity hooks refused: LTO kernel ({} enables CONFIG_LTO_*; inlined hook-target copies escape fentry)",
                        modules_config_path.display()
                    ));
                }
                return None;
            }
            Err(error) => {
                failures.push(format!("{}: {error}", modules_config_path.display()));
            }
        }
    }
    Some(format!(
        "instance continuity hooks refused: LTO status unverifiable (no verifiable kernel config for release {release}: {})",
        failures.join("; ")
    ))
}

/// Kernel LTO preflight (B2): refuses the hooks on LTO kernels, and on
/// kernels whose LTO status is unverifiable, with a named reason each.
/// Reads the RUNNING release's config from the first verifiable source in
/// order: the distro `/boot/config-{release}` (absent on Arch/NixOS), the
/// kernel's own `/proc/config.gz` (IKCONFIG_PROC; gzip via flate2's
/// pure-Rust backend), then `/lib/modules/{release}/build/.config` only
/// when the build tree provably names the running release. Nothing
/// verifiable refuses; LTO-off is never assumed. A kallsyms ThinLTO
/// (`.llvm.`) signal is deliberately unused: presence implies LTO but
/// absence does not imply non-LTO (full LTO, restricted kallsyms), so it
/// is unsound in the allow direction. Stage 5 per-cell preflight
/// re-verifies LTO status on every matrix cell (DR-T3A-2); relaxing the
/// unverifiable arm needs an owner decision.
pub(super) fn lto_refusal() -> Option<String> {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|release| release.trim().to_owned())
        .unwrap_or_default();
    if release.is_empty() {
        return Some(
            "instance continuity hooks refused: cannot read the running kernel release".to_string(),
        );
    }
    let boot = format!("/boot/config-{release}");
    let modules_base = format!("/lib/modules/{release}/build");
    let modules_config = format!("{modules_base}/.config");
    let kernel_release = format!("{modules_base}/include/config/kernel.release");
    let utsrelease = format!("{modules_base}/include/generated/utsrelease.h");
    lto_refusal_for_release(
        &release,
        Path::new(&boot),
        Path::new("/proc/config.gz"),
        Path::new(&modules_config),
        Path::new(&kernel_release),
        Path::new(&utsrelease),
    )
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
        let refused = |reason| PreparedInstanceTracking {
            programs: Err(HookPreparationRefusal { reason }),
        };
        if hooks_disabled_by_env() {
            return refused(format!(
                "instance continuity hooks refused: disabled by {DISABLE_HOOKS_ENV}=1 (Stage A overhead measurement)"
            ));
        }
        if !policy.wants_instance_hooks() {
            return refused(
                "instance continuity hooks refused: aggregate-only (metrics) sessions never join per-call records to load instances (Task 1d overhead gate)"
                    .to_string(),
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
                apply_prepare_refusal(coverage, &mut tracking, refusal.reason);
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

    /// The hook recursion-miss total at the last audit and the number of
    /// fault raises those misses caused. Counts only, for the stop line
    /// and the router's miss-era carry.
    pub(super) fn miss_totals(&self) -> (u64, u64) {
        let misses = self
            .hook_misses
            .lock()
            .map(|baseline| {
                baseline
                    .values()
                    .fold(0u64, |sum, n| sum.saturating_add(*n))
            })
            .unwrap_or(0);
        (
            misses,
            self.miss_raises.load(std::sync::atomic::Ordering::SeqCst),
        )
    }

    /// Returns whether this audit raised the fault era for new misses.
    pub(super) fn audit(
        &self,
        ebpf: &Ebpf,
        coverage: &super::image_query::CoverageControl,
    ) -> Result<bool> {
        let Ok(mut misses) = self.hook_misses.lock() else {
            coverage.fail();
            bail!("image hook miss baseline poisoned");
        };
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
            &mut misses,
            || {
                let (raised, won) = InstanceMaps { ebpf }.raise_fault_won()?;
                // Only a raise that moved the cell itself counts: the capture
                // names a miss era only when the fault moved by exactly the
                // raises the misses won.
                if won {
                    self.miss_raises
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                Ok(raised)
            },
        )
    }

    fn load_hooks(ebpf: &mut Ebpf, btf: &Btf) -> Result<LoadedInstancePrograms> {
        let host =
            super::host_btf::shared().context("loading required vmlinux BTF for instance hooks")?;
        let exec = resolve_exec_release_target(host, btf)?;
        let copy = resolve_copy_vma_target(host, btf)?;
        let targets = HookTargets { copy, exec };
        load_instance_programs_with(ebpf, targets, |ebpf, program, target| {
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
        self.active_targets = Some(loaded.targets);
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

    /// The active instance-hook program names: the legacy set until hooks
    /// attach, the resolved set after.
    pub(crate) fn active_program_names(&self) -> [&'static str; 4] {
        let triples = active_instance_programs(self.active_targets.unwrap_or(HookTargets {
            copy: CopyVmaTarget::Legacy,
            exec: ExecReleaseTarget::ExecMmRelease,
        }));
        [triples[0].0, triples[1].0, triples[2].0, triples[3].0]
    }

    /// The hook programs' statistics, summed. `run_time_ns`/`run_cnt` need
    /// `kernel.bpf_stats_enabled`; `recursion_misses` is always counted.
    pub(crate) fn hook_stats(&self, ebpf: &Ebpf) -> Result<Vec<(&'static str, HookStats)>> {
        self.active_program_names()
            .into_iter()
            .map(|program| {
                let fd = ebpf
                    .program(program)
                    .with_context(|| format!("program {program}"))?
                    .fd()
                    .with_context(|| format!("program {program} fd"))?;
                Ok((program, prog_stats(fd.as_fd())?))
            })
            .collect()
    }
}

/// Verify the actual BTF prototype rather than accepting the function name
/// alone. This is separate from the no-LTO cross-file call coverage premise.
pub(super) fn validate_exec_release_proto(
    host: &super::host_btf::HostBtf,
    btf: &Btf,
) -> Result<()> {
    let raw = host
        .original_bytes_for(btf)
        .context("instance hook BTF differs from cached host BTF")?;
    ensure!(
        exec_release_proto_is_exact(raw),
        "no exact exec-release hook: exec_mm_release must be void(task_struct *, mm_struct *) or exec_mmap must be int(linux_binprm *)"
    );
    Ok(())
}

/// Verify the actual `copy_vma` BTF prototype rather than accepting the
/// function name alone: exactly one `copy_vma` with the exact 5-argument
/// legacy or 6/7-argument extended shape.
fn validate_copy_vma_proto(host: &super::host_btf::HostBtf, btf: &Btf) -> Result<()> {
    let raw = host
        .original_bytes_for(btf)
        .context("instance hook BTF differs from cached host BTF")?;
    ensure!(
        copy_vma_proto_kind(raw).is_some(),
        "no exact copy_vma hook: copy_vma must be struct vm_area_struct *(vmap, addr, len, pgoff[, anon_pgoff], need_rmap_locks[, keep_source])"
    );
    Ok(())
}

pub(super) fn exec_release_proto_is_exact(raw: &[u8]) -> bool {
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

/// Whether the host BTF carries exactly one `exec_mmap` with the exact
/// int(linux_binprm *) prototype the 7.3+ hook needs: one argument, so the
/// fexit return slot is ctx[1], and an integer return, so zero means the new
/// mm installed. Mirrors [`exec_release_proto_is_exact`]; the legacy parser
/// is untouched so its pinned behavior cannot drift.
fn exec_mmap_proto_is_exact(raw: &[u8]) -> bool {
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
                && word(node, 0).and_then(name) == Some(b"exec_mmap".as_slice())
        });
        let function = functions.next()?;
        if functions.next().is_some() {
            return Some(false);
        }
        let proto = resolve(word(function, 8)?)?;
        if word(proto, 4)? != (13 << 24 | 1) {
            return Some(false);
        }
        let ret = resolve(word(proto, 8)?)?;
        if (word(ret, 4)? >> 24) & 31 != 1 {
            return Some(false);
        }
        // exec_mmap returns int: a 4-byte signed INT, so the hook's
        // (int)ctx[1] success check reads the whole return and nothing else.
        if word(ret, 8)? != 4 || word(ret, 12)? != 0x0100_0020 {
            return Some(false);
        }
        pointee(word(proto, 16)?, b"linux_binprm")
    };
    checked().unwrap_or(false)
}

/// Which exact `copy_vma` prototype the host BTF carries, if any: the
/// 5-argument legacy shape (fixed fexit slot `ctx[5]`) or the 6/7-argument
/// extended shape (`keep_source` from the stable backports of
/// 838bb60dc215, `anon_pgoff` from 7.3; the return slot moves, so the hook
/// reads it through `bpf_get_func_ret`). All three spell the return as
/// `struct vm_area_struct *`, `vmap` as a double pointer to it, the
/// offsets as 8-byte unsigned (`pgoff_t`), `need_rmap_locks` as `bool *`
/// and `keep_source` as `bool`. Mirrors [`exec_mmap_proto_is_exact`];
/// the exec parsers are untouched so their pinned behavior cannot drift.
fn copy_vma_proto_kind(raw: &[u8]) -> Option<CopyVmaTarget> {
    let word = |bytes: &[u8], at: usize| -> Option<u32> {
        Some(u32::from_le_bytes(
            bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
        ))
    };
    let checked = || -> Option<Option<CopyVmaTarget>> {
        if raw.get(..4)? != [0x9f, 0xeb, 1, 0] {
            return Some(None);
        }
        let header = word(raw, 4)? as usize;
        if header < 24 {
            return Some(None);
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
                _ => return Some(None),
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
        let kind_of = |node: &[u8]| -> Option<u32> { Some((word(node, 4)? >> 24) & 31) };
        // An 8-byte unsigned offset (`pgoff_t`): INT, no encoding, 64 bits.
        let ulong = |id: u32| -> Option<bool> {
            let node = resolve(id)?;
            Some(kind_of(node)? == 1 && word(node, 8)? == 8 && word(node, 12)? == 0x0000_0040)
        };
        // A kernel `bool` (through the `bool` typedef or spelled `_Bool`
        // directly): 1-byte BOOL-encoded INT, never a plain char.
        let boolean = |id: u32| -> Option<bool> {
            let node = resolve(id)?;
            Some(kind_of(node)? == 1 && word(node, 8)? == 1 && word(node, 12)? == 0x0400_0008)
        };
        let vma_pointee = |id: u32| -> Option<bool> {
            let pointer = resolve(id)?;
            if kind_of(pointer)? != 2 {
                return Some(false);
            }
            let target = resolve(word(pointer, 8)?)?;
            Some(kind_of(target)? == 4 && name(word(target, 0)?)? == b"vm_area_struct")
        };
        let vma_double_pointee = |id: u32| -> Option<bool> {
            let outer = resolve(id)?;
            if kind_of(outer)? != 2 {
                return Some(false);
            }
            vma_pointee(word(outer, 8)?)
        };
        let bool_pointee = |id: u32| -> Option<bool> {
            let pointer = resolve(id)?;
            if kind_of(pointer)? != 2 {
                return Some(false);
            }
            boolean(word(pointer, 8)?)
        };
        let mut functions = nodes.iter().skip(1).filter(|node| {
            word(node, 4).is_some_and(|info| (info >> 24) & 31 == 12)
                && word(node, 0).and_then(name) == Some(b"copy_vma".as_slice())
        });
        let function = functions.next()?;
        if functions.next().is_some() {
            return Some(None);
        }
        let proto = resolve(word(function, 8)?)?;
        let arity = word(proto, 4)?;
        let count = (arity & 65535) as usize;
        if (arity >> 24) & 31 != 13 || !matches!(count, 5..=7) {
            return Some(None);
        }
        if !vma_pointee(word(proto, 8)?)? {
            return Some(None);
        }
        let arg = |index: usize| -> Option<u32> { word(proto, 16 + index.checked_mul(8)?) };
        if !vma_double_pointee(arg(0)?)? {
            return Some(None);
        }
        // (addr, len, pgoff) are always next; the 7-argument shape adds
        // anon_pgoff, then need_rmap_locks, then the by-value keep_source
        // on the extended shapes only.
        let mut next = 1;
        for _ in 0..3 {
            if !ulong(arg(next)?)? {
                return Some(None);
            }
            next += 1;
        }
        if count == 7 {
            if !ulong(arg(next)?)? {
                return Some(None);
            }
            next += 1;
        }
        if !bool_pointee(arg(next)?)? {
            return Some(None);
        }
        next += 1;
        if count >= 6 {
            if !boolean(arg(next)?)? {
                return Some(None);
            }
            next += 1;
        }
        if next != count {
            return Some(None);
        }
        Some(if count == 5 {
            Some(CopyVmaTarget::Legacy)
        } else {
            Some(CopyVmaTarget::FuncRet)
        })
    };
    checked().unwrap_or(None)
}

/// The calibration protocol: arm `INSTANCE_CALIB` with this thread, map one
/// page of the pinned fd, and require the hook's record of exactly that
/// mapping start. The recorded `{s_dev, i_ino}` is the kernel identity every
/// hook will compute for this file: the filesystem-wide `s_dev` (shared by
/// every btrfs subvolume, not the subvolume's anonymous device) and the
/// real inode.
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
/// (both read `vm_file->f_inode`; maps probed on 6.6.157 for upper-only
/// and lower-layer files; joins proven live for upper-only). On 6.8+ the
/// raw key matches and the calibration key is normally dead. Pre-6.8 the
/// key also selects other mounts of the same lower file (shared backing
/// line, probed `(52, 11)` on both mounts on 6.6); on 6.8+ it matches
/// only direct mappings of the backing filesystem. Identity confirmation
/// still gates every selected candidate, so such extras cost extra
/// `map_files` stats (a failing stat refuses the scan); no false join
/// beyond what the raw key already admits on 6.8+ (a second mount
/// compares unequal: `(66, 11)` vs `(68, 11)` on 6.6, `(69, 11)` vs
/// `(71, 11)` on 7.0).
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
    use p11scope_ebpf_common::journal_marker::MarkerRead;
    let record = rows.read_marker_row();
    let control = rows
        .read_admission_control()
        .map_err(|_| BirthObservationRefusal::RowUnreadable)?;
    // Attach-observed births claim no exec publication, so a
    // pre-existing process may have no marker row at all: its
    // absence reads as the unmarked word. Custody and the control
    // row still refuse closed. Every other kind keeps the
    // readable-row-first refusal order.
    let record = if birth == BirthKind::AttachObserved {
        record.ok()
    } else {
        Some(record.map_err(|_| BirthObservationRefusal::RowUnreadable)?)
    };
    let (image, custody) = common_retained_birth_words(&control, binding, attachment, admitted)?;
    let marker_word = if birth == BirthKind::AttachObserved {
        match record {
            Some(record) => {
                // A row stamped by a *later* closure than the
                // sealed one is native truth from the future: it
                // cannot witness this closure's birth. Older (or
                // zero) stamps are the ordinary pre-existing case.
                if record.exec_attach_gen > attachment.generation() {
                    return Err(BirthObservationRefusal::GenerationMismatch);
                }
                match p11scope_ebpf_common::journal_marker::read_word(record.journal_bootstrap) {
                    MarkerRead::Unpublished => 0,
                    MarkerRead::Ready(exec) if exec == image.1 => record.journal_bootstrap,
                    // v0.7.0 issue 1: a DIRTY word passes through into
                    // attach-observed evidence. DIRTY proves a lost
                    // prefix (a watched call was refused or lost), which
                    // attach-observed accounts as not-attributed; it
                    // never authorizes exec or absence. The seal
                    // re-checks the same fresh word through the same
                    // rule, so the birth keeps sealing.
                    MarkerRead::Dirty => record.journal_bootstrap,
                    _ => return Err(BirthObservationRefusal::MarkerNotReady),
                }
            }
            None => 0,
        }
    } else {
        let record = record.expect("non-attach kinds unwrapped the row above");
        match birth {
            BirthKind::ExecMarker => {
                if p11scope_ebpf_common::journal_marker::read_word(record.journal_bootstrap)
                    != MarkerRead::Ready(image.1)
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
            BirthKind::AbsenceAppearance | BirthKind::AttachObserved => {}
        }
        record.journal_bootstrap
    };
    let token = SessionGrantToken(());
    let evidence = crate::semantics_objects::journal::SessionBirthEvidence::issue(
        &token,
        image,
        marker_word,
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

pub(crate) struct LiveBirthRows<'m> {
    maps: &'m InstanceMaps<'m>,
    pin: std::sync::Arc<crate::process::PidPin>,
}

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
/// Detailed object must match this compilation's marker selection; a counter
/// bank object with the map is refused without touching it.
/// UNRUN: live map access stays out of tests; the verdict below is
/// pinned over pure values.
pub(super) fn prepare_marker_control(ebpf: &aya::Ebpf, roots: StaticRoots) -> Result<()> {
    const NAME: &str = "JOURNAL_MARKER_CTL";
    let expected = cfg!(p11scope_birth_marker);
    let map = ebpf.map(NAME);
    if roots == StaticRoots::CounterBanks || !expected {
        return marker_control_verdict(map.is_some(), roots, expected, None);
    }
    let Some(map) = map else {
        return marker_control_verdict(false, roots, expected, None);
    };
    let data = super::policy_map_data(NAME, map)?;
    super::validate_map_metadata(NAME, data, super::map_metadata(MapType::Array, 4, 16, 1, 0))?;
    let control: Array<&MapData, JournalAdmissionControl> = Array::try_from(map)?;
    let readback = control
        .get(&0, 0)
        .with_context(|| format!("reading {NAME} control row"))?;
    marker_control_verdict(true, roots, expected, Some(readback))?;
    super::freeze_map(NAME, map)
}

/// Pure control-row verdict behind [`prepare_marker_control`]: a
/// Detailed session requires the map exactly when this build enabled it. An
/// enabled map needs zero readback before freezing; counter banks forbid it
/// independently of the Detailed build selection.
fn marker_control_verdict(
    present: bool,
    roots: StaticRoots,
    expected: bool,
    readback: Option<JournalAdmissionControl>,
) -> Result<()> {
    match (roots, expected, present) {
        (StaticRoots::CounterBanks, _, true) => {
            bail!("JOURNAL_MARKER_CTL present in a counter bank object")
        }
        (StaticRoots::CounterBanks, _, false) | (StaticRoots::Detailed, false, false) => Ok(()),
        (StaticRoots::Detailed, false, true) => {
            bail!("JOURNAL_MARKER_CTL present in a marker-off Detailed object (stale build)")
        }
        (StaticRoots::Detailed, true, false) => {
            bail!("JOURNAL_MARKER_CTL missing from the Detailed object (stale build)")
        }
        (StaticRoots::Detailed, true, true) => match readback {
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

/// Exec-marker birth source: each take re-runs the exec observation
/// through the injected reader against live native state; the spent
/// issuance token drops with the take (the grant was issued at
/// attestation). Compiled into production builds but constructed only by
/// tests: the live seal checks births through `observe_retained_birth`
/// in `semantic_capture`. Live exec-marker births can succeed in opted-in
/// `--key-operations` sessions, where the journal object publishes both
/// the generation and the READY writer.
#[allow(dead_code)] // Production-compiled, test-constructed (see above).
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

/// Test-only absence-appearance birth source: each take re-runs the
/// absence observation (committed negative witness, advanced-epoch
/// appearance) against injected native state. The live seal checks
/// absence births through `observe_retained_birth` in `semantic_capture`.
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
        self.raise_fault_won().map(|(raised, _)| raised)
    }

    /// [`Self::raise_fault`] reporting whether this raise moved the cell
    /// itself (won its compare-and-swap).
    pub(crate) fn raise_fault_won(&self) -> Result<(u64, bool)> {
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
fn raise_mmapped_fault(fd: BorrowedFd<'_>) -> Result<(u64, bool)> {
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
    let raised = raise_fault_cell_won(cell);
    // SAFETY: exactly the mapping created above.
    unsafe { libc::munmap(address, 4096) };
    raised
}

pub(super) fn raise_fault_cell(cell: &std::sync::atomic::AtomicU64) -> Result<u64> {
    raise_fault_cell_won(cell).map(|(raised, _)| raised)
}

/// [`raise_fault_cell`] that also reports whether this raise won its own
/// compare-and-swap (moved the cell itself) rather than finding it already
/// moved by another raiser.
pub(super) fn raise_fault_cell_won(cell: &std::sync::atomic::AtomicU64) -> Result<(u64, bool)> {
    use std::sync::atomic::Ordering;
    raise_fault_with_won(cell.load(Ordering::SeqCst), |seen, next| {
        cell.compare_exchange(seen, next, Ordering::SeqCst, Ordering::SeqCst)
    })
}

/// The bounded raise over one compare-and-swap seam (the real atomic cell
/// in production; a scripted swap in the contention twins).
fn raise_fault_with(
    seen: u64,
    swap: impl FnMut(u64, u64) -> std::result::Result<u64, u64>,
) -> Result<u64> {
    raise_fault_with_won(seen, swap).map(|(raised, _)| raised)
}

fn raise_fault_with_won(
    mut seen: u64,
    mut swap: impl FnMut(u64, u64) -> std::result::Result<u64, u64>,
) -> Result<(u64, bool)> {
    for _ in 0..8 {
        ensure!(
            seen <= u64::from(u32::MAX),
            "instance fault generation exhausted"
        );
        let next = seen + 1;
        match swap(seen, next) {
            Ok(_) => {
                ensure!(
                    next <= u64::from(u32::MAX),
                    "instance fault generation exhausted"
                );
                return Ok((next, true));
            }
            // A lost swap means another raiser (BPF or userspace) already
            // moved the cell past the value read: that is all a raise needs.
            Err(current) if current > seen => {
                ensure!(
                    current <= u64::from(u32::MAX),
                    "instance fault generation exhausted"
                );
                return Ok((current, false));
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

    /// A lost swap means another raiser already moved the cell past the
    /// value read, which is all a raise needs: no retry storm can latch
    /// coverage, and the exhaustion checks still hold.
    #[test]
    fn a_raise_reports_whether_it_moved_the_cell_itself() {
        assert_eq!(
            super::raise_fault_with_won(41, |seen, next| {
                assert_eq!((seen, next), (41, 42));
                Ok(seen)
            })
            .unwrap(),
            (42, true),
            "a won swap moved the cell"
        );
        assert_eq!(
            super::raise_fault_with_won(41, |_, _| Err(43)).unwrap(),
            (43, false),
            "a swap lost to another raiser did not"
        );
    }

    #[test]
    fn a_raise_lost_to_other_raisers_still_succeeds() {
        let mut cell = 41u64;
        let raised = super::raise_fault_with(41, |seen, _| {
            // Another raiser wins every swap.
            cell = cell.max(seen) + 1;
            Err(cell)
        });
        assert_eq!(raised.unwrap(), 42);
        let exhausted =
            super::raise_fault_with(u64::from(u32::MAX) - 1, |_, _| Err(u64::from(u32::MAX) + 1));
        assert!(
            exhausted.is_err(),
            "a lost swap to exhaustion still refuses"
        );
    }

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
        // A raise lost to another raiser succeeds with the value the winner
        // installed (see `a_raise_lost_to_other_raisers_still_succeeds`), so
        // one to three writers report the last generation depending on the
        // interleaving; exactly one of them moved the cell itself.
        let cell = Arc::new(AtomicU64::new(u64::from(u32::MAX) - 1));
        let barrier = Arc::new(Barrier::new(4));
        let writers: Vec<_> = (0..3)
            .map(|_| {
                let cell = Arc::clone(&cell);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    super::raise_fault_cell_won(&cell)
                })
            })
            .collect();
        barrier.wait();
        let results: Vec<_> = writers
            .into_iter()
            .map(|writer| writer.join().unwrap())
            .collect();
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Ok((_, true))))
                .count(),
            1,
            "exactly one writer moves MAX-1 to MAX"
        );
        assert!(
            results
                .iter()
                .filter_map(|result| result.as_ref().ok())
                .all(|(raised, _)| *raised == u64::from(u32::MAX)),
            "every reported raise is the last representable generation"
        );
        let settled = cell.load(Ordering::SeqCst);
        assert!(
            settled == u64::from(u32::MAX) || settled == u64::from(u32::MAX) + 1,
            "the cell holds MAX or the refusal sentinel, never a reopened era"
        );
        assert!(raise_fault_cell(&cell).is_err());
        assert_eq!(cell.load(Ordering::SeqCst), u64::from(u32::MAX) + 1);
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
        // A load baseline names the active hook set (legacy or 7.3+);
        // without one only the legacy names validate.
        let known = match expected {
            Some(baseline) => baseline.contains_key(name),
            None => INSTANCE_PROGRAMS
                .iter()
                .any(|(required, _)| *required == name),
        };
        ensure!(
            stats.program_id != 0 && known && ids.insert(name, stats.program_id).is_none(),
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

#[allow(clippy::too_many_arguments)] // Each live read stays an injectable seam for the latch and fault-era twins.
pub(super) fn audit_image_hooks_with(
    coverage: &super::image_query::CoverageControl,
    active: bool,
    link_count: usize,
    expected: &BTreeMap<&'static str, u32>,
    read_ftrace: impl FnOnce() -> Result<String>,
    read_stats: impl FnOnce() -> Result<Vec<(&'static str, HookStats)>>,
    read_faults: impl FnOnce() -> Result<(u64, u64)>,
    misses: &mut BTreeMap<&'static str, u64>,
    raise_fault: impl FnOnce() -> Result<u64>,
) -> Result<bool> {
    let result = (|| {
        ensure!(active && coverage.enabled(), "image continuity unavailable");
        let mut seen = BTreeMap::new();
        validate_hook_health_with(link_count, Some(expected), read_ftrace, || {
            let stats = read_stats()?;
            for (name, stat) in &stats {
                seen.insert(*name, stat.recursion_misses);
            }
            Ok(stats)
        })?;
        // A recursion miss is one skipped hook run (a preempted trampoline
        // on a busy host), so some mapping change went unrecorded. That is
        // a fault, not lost coverage: raise the era before reading it, so
        // every call stamped across the miss (collected before this audit)
        // fails as a counted coverage fault and later calls re-prove. A
        // counter that went backwards, or a failed raise, stays permanent.
        // The exec-release hook keeps the permanent latch: BPF treats a lost
        // exec invalidation as permanent too, and it shows no misses even
        // under an exec storm, so the latch costs nothing in practice.
        let mut grew = false;
        for (name, now) in &seen {
            let before = misses.get(name).copied().unwrap_or(0);
            ensure!(*now >= before, "image hook miss counter regressed");
            ensure!(
                *now == before
                    || (*name != INSTANCE_PROGRAMS[3].0 && *name != EXEC_RELEASE_MMAP_PROGRAM),
                "image exec-release hook missed"
            );
            grew |= *now > before;
        }
        if grew {
            raise_fault()?;
        }
        *misses = seen;
        let (sticky, fault) = read_faults()?;
        ensure!(
            sticky == 0 && fault <= u64::from(u32::MAX),
            "instance continuity fault/exhaustion"
        );
        ensure!(
            coverage.enabled(),
            "image continuity failed during health audit"
        );
        Ok(grew)
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
    fn loader_only_doctor_result_carries_no_marker_flag() {
        // 6.05 step 2 negative twin (loader-only doctor): the doctor's
        // target-availability preflight reads no marker row, observes no
        // birth and publishes no marker flag. A loader-only doctor result
        // must never be mistaken for birth evidence: no marker word,
        // birth observation or native birth leaf is referenced.
        let doctor = std::fs::read_to_string("src/doctor.rs").expect("doctor source reads");
        for linkage in [
            "journal_bootstrap",
            "observe_exec_birth",
            "observe_retained_birth",
            "BirthAdmissionBinding",
            "MARKER_READY",
            "MARKER_DIRTY",
            "ready_word",
            "p11_instance_exec_birth",
            "p11_instance_scope_gap",
            "JOURNAL_MARKER_CTL",
            "MARKER_UNPUBLISHED",
            "MarkerRead",
            "read_word",
            "MARKER_ADMIT_CAP",
            "JournalAdmissionControl",
        ] {
            assert!(
                !doctor.contains(linkage),
                "loader-only doctor must not reference {linkage}"
            );
        }
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
        let names: Vec<&'static str> = super::INSTANCE_PROGRAMS
            .iter()
            .map(|(name, _)| *name)
            .collect();
        healthy_hook_stats_for(&names)
    }

    fn healthy_hook_stats_for(names: &[&'static str]) -> Vec<(&'static str, super::HookStats)> {
        names
            .iter()
            .enumerate()
            .map(|(index, name)| {
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
    fn hook_health_accepts_the_resolved_mmap_set() {
        let names: Vec<&'static str> = super::active_instance_programs(super::HookTargets {
            copy: super::CopyVmaTarget::Legacy,
            exec: super::ExecReleaseTarget::ExecMmap,
        })
        .iter()
        .map(|(program, _)| *program)
        .collect();
        assert_eq!(names[3], super::EXEC_RELEASE_MMAP_PROGRAM);
        let stats = healthy_hook_stats_for(&names);
        let expected = stats
            .iter()
            .map(|(name, stats)| (*name, stats.program_id))
            .collect();
        super::validate_hook_health_with(4, Some(&expected), || Ok("1".into()), || Ok(stats))
            .expect("the resolved mmap set validates against its load baseline");
    }

    #[test]
    fn hook_health_accepts_every_resolved_hook_set() {
        use super::{CopyVmaTarget, ExecReleaseTarget, HookTargets};
        for copy in [CopyVmaTarget::Legacy, CopyVmaTarget::FuncRet] {
            for exec in [
                ExecReleaseTarget::ExecMmRelease,
                ExecReleaseTarget::ExecMmap,
            ] {
                let names: Vec<&'static str> =
                    super::active_instance_programs(HookTargets { copy, exec })
                        .iter()
                        .map(|(program, _)| *program)
                        .collect();
                assert_eq!(
                    names[2],
                    if copy == CopyVmaTarget::FuncRet {
                        super::COPY_VMA_RET_PROGRAM
                    } else {
                        "p11_inst_vma_copy"
                    }
                );
                assert_eq!(
                    names[3],
                    if exec == ExecReleaseTarget::ExecMmap {
                        super::EXEC_RELEASE_MMAP_PROGRAM
                    } else {
                        "p11_image_exec_release"
                    }
                );
                let stats = healthy_hook_stats_for(&names);
                let expected = stats
                    .iter()
                    .map(|(name, stats)| (*name, stats.program_id))
                    .collect();
                super::validate_hook_health_with(
                    4,
                    Some(&expected),
                    || Ok("1".into()),
                    || Ok(stats),
                )
                .unwrap_or_else(|error| {
                    panic!("the resolved {copy:?}/{exec:?} set validates: {error:#}")
                });
            }
        }
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
                &mut std::collections::BTreeMap::new(),
                || Ok(1),
            );
            assert!(result.is_err(), "health case {case} was accepted");
            assert!(!coverage.enabled());
            assert!(coverage.enable().is_err());
        }
        // A recursion-miss counter that runs backwards, or a fault raise
        // that fails, cannot be scoped and still latches permanently.
        for regressed in [true, false] {
            let coverage = super::super::image_query::CoverageControl::test_owner(true);
            let mut misses = std::collections::BTreeMap::new();
            let mut stats = healthy_hook_stats();
            stats[0].1.recursion_misses = 1;
            if regressed {
                misses.insert(stats[0].0, 2);
            }
            assert!(
                super::audit_image_hooks_with(
                    &coverage,
                    true,
                    4,
                    &expected,
                    || Ok("1".into()),
                    || Ok(stats),
                    || Ok((0, 0)),
                    &mut misses,
                    || Err(anyhow::anyhow!("unwritable fault cell")),
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
                    &mut std::collections::BTreeMap::new(),
                    || Ok(1),
                )
                .is_err()
            );
            assert!(coverage.enable().is_err());
        }
    }

    /// A hook recursion miss (a preempted trampoline on a busy host) is a
    /// scoped fault: the audit raises the fault era so no call stamped
    /// across the miss can join, and coverage stays enabled so later
    /// calls re-prove instead of shedding for the rest of the capture.
    #[test]
    fn production_hook_recursion_misses_raise_the_fault_era_without_latching() {
        let expected: std::collections::BTreeMap<_, _> = healthy_hook_stats()
            .into_iter()
            .map(|(name, stats)| (name, stats.program_id))
            .collect();
        // The exec-release hook (index 3) keeps the permanent latch; see
        // `production_exec_release_hook_misses_still_latch_coverage`.
        for missed in 0..super::INSTANCE_PROGRAMS.len() - 1 {
            let coverage = super::super::image_query::CoverageControl::test_owner(true);
            let mut misses = std::collections::BTreeMap::new();
            let raises = std::cell::Cell::new(0);
            let mut audit = |count: u64| {
                let mut stats = healthy_hook_stats();
                stats[missed].1.recursion_misses = count;
                super::audit_image_hooks_with(
                    &coverage,
                    true,
                    4,
                    &expected,
                    || Ok("1".into()),
                    || Ok(stats),
                    || Ok((0, raises.get())),
                    &mut misses,
                    || {
                        raises.set(raises.get() + 1);
                        Ok(raises.get())
                    },
                )
            };
            assert!(audit(0).is_ok());
            assert_eq!(raises.get(), 0, "no miss, no fault");
            let result = audit(1);
            assert!(
                result.is_ok(),
                "a recursion miss is not a coverage failure: {result:?}"
            );
            assert_eq!(raises.get(), 1, "a new miss raises the fault era once");
            assert!(audit(1).is_ok());
            assert_eq!(raises.get(), 1, "an unchanged count raises nothing");
            assert!(audit(5).is_ok());
            assert_eq!(raises.get(), 2, "each later growth raises again");
            assert!(coverage.enabled(), "coverage survives recursion misses");
        }
    }

    /// BPF treats a lost exec invalidation as permanent, so a miss on the
    /// exec-release hook (either variant) still latches coverage off.
    #[test]
    fn production_exec_release_hook_misses_still_latch_coverage() {
        for exec in [
            super::INSTANCE_PROGRAMS[3].0,
            super::EXEC_RELEASE_MMAP_PROGRAM,
        ] {
            let mut names: Vec<&'static str> = super::INSTANCE_PROGRAMS
                .iter()
                .map(|(name, _)| *name)
                .collect();
            names[3] = exec;
            let expected: std::collections::BTreeMap<_, _> = healthy_hook_stats_for(&names)
                .into_iter()
                .map(|(name, stats)| (name, stats.program_id))
                .collect();
            let coverage = super::super::image_query::CoverageControl::test_owner(true);
            let mut stats = healthy_hook_stats_for(&names);
            stats[3].1.recursion_misses = 1;
            let raises = std::cell::Cell::new(0);
            let result = super::audit_image_hooks_with(
                &coverage,
                true,
                4,
                &expected,
                || Ok("1".into()),
                || Ok(stats),
                || Ok((0, 0)),
                &mut std::collections::BTreeMap::new(),
                || {
                    raises.set(raises.get() + 1);
                    Ok(1)
                },
            );
            assert!(result.is_err(), "{exec}: an exec-release miss latches");
            assert_eq!(raises.get(), 0);
            assert!(!coverage.enabled());
            assert!(coverage.enable().is_err());
        }
    }

    #[test]
    fn optional_hook_load_refusal_never_attaches_and_complete_load_waits_for_activation() {
        for fail in 0..=super::INSTANCE_PROGRAMS.len() {
            let coverage = super::super::image_query::CoverageControl::test_owner(false);
            let mut calls = Vec::new();
            let mut loaded_count = 0;
            let prepared = super::load_instance_programs_with(
                &mut calls,
                super::HookTargets {
                    copy: super::CopyVmaTarget::Legacy,
                    exec: super::ExecReleaseTarget::ExecMmRelease,
                },
                |calls, program, _| {
                    assert!(calls.iter().all(|(operation, _)| *operation == "load"));
                    calls.push(("load", program));
                    if loaded_count == fail {
                        anyhow::bail!("owned load refusal: {program}");
                    }
                    loaded_count += 1;
                    Ok(loaded_count as u32)
                },
            );
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
        let loaded = super::load_instance_programs_with(
            &mut next,
            super::HookTargets {
                copy: super::CopyVmaTarget::Legacy,
                exec: super::ExecReleaseTarget::ExecMmRelease,
            },
            |next, _, _| {
                *next += 1;
                Ok(*next)
            },
        )
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

    /// A prepare refusal (LTO-unverifiable kernels, aggregate sessions)
    /// records its reason and leaves coverage disabled (never-active),
    /// never failed: only a mid-run failure fails coverage. The BPF
    /// join gate consults exactly this distinction.
    #[test]
    fn prepare_refusal_records_reason_and_leaves_coverage_disabled() {
        let coverage = super::super::image_query::CoverageControl::test_owner(false);
        let mut tracking = super::InstanceTracking::default();
        super::apply_prepare_refusal(
            &coverage,
            &mut tracking,
            "instance continuity hooks refused: test refusal".to_string(),
        );
        assert_eq!(
            tracking.refused(),
            Some("instance continuity hooks refused: test refusal")
        );
        assert!(
            coverage.enable().is_ok(),
            "a prepare refusal must leave coverage disabled, not failed"
        );
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

    /// BTF blob carrying both exec-release hook families: the legacy
    /// `exec_mm_release` void(task_struct *, mm_struct *) shape and the 7.3+
    /// `exec_mmap` int(linux_binprm *) shape. The flags select which FUNC
    /// records exist; shared types are always present with stable ids.
    fn exec_hook_btf_fixture(
        with_legacy: bool,
        with_mmap: bool,
        header_len: u32,
        string_gap: usize,
    ) -> Vec<u8> {
        let strings = b"\0task_struct\0mm_struct\0linux_binprm\0exec_mm_release\0exec_mmap\0int\0";
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
            4 << 24,
            1, // linux_binprm
            0,
            2 << 24,
            6, // pointer to bprm
            62,
            1 << 24,
            4,
            0x0100_0020, // signed 32-bit int
            0,
            (13 << 24) | 1,
            8,
            0,
            7, // one-argument int proto
        ];
        let mut types: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        if with_legacy {
            for word in [36u32, (12 << 24) | 1, 5] {
                types.extend(word.to_le_bytes());
            }
        }
        if with_mmap {
            for word in [52u32, (12 << 24) | 1, 9] {
                types.extend(word.to_le_bytes());
            }
        }
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

    fn resolve_fixture(bytes: Vec<u8>) -> Result<super::ExecReleaseTarget, String> {
        use super::super::host_btf;
        let cell = std::sync::OnceLock::new();
        let host = host_btf::cached(&cell, || Ok(bytes)).map_err(|error| error.to_string())?;
        super::resolve_exec_release_target(host, host.btf()).map_err(|error| error.to_string())
    }

    #[test]
    fn resolver_prefers_legacy_when_present() {
        for (legacy, mmap) in [(true, false), (true, true)] {
            let bytes = exec_hook_btf_fixture(legacy, mmap, 24, 0);
            assert_eq!(
                resolve_fixture(bytes).unwrap(),
                super::ExecReleaseTarget::ExecMmRelease
            );
        }
    }

    #[test]
    fn resolver_selects_mmap_without_legacy() {
        let bytes = exec_hook_btf_fixture(false, true, 24, 0);
        assert_eq!(
            resolve_fixture(bytes).unwrap(),
            super::ExecReleaseTarget::ExecMmap
        );
    }

    #[test]
    fn resolver_refuses_without_either_hook() {
        let bytes = exec_hook_btf_fixture(false, false, 24, 0);
        assert_eq!(
            resolve_fixture(bytes).unwrap_err(),
            "no exact exec-release hook: exec_mm_release must be void(task_struct *, mm_struct *) or exec_mmap must be int(linux_binprm *)"
        );
    }

    #[test]
    fn resolver_rejects_foreign_parse() {
        use super::super::host_btf;
        let bytes = exec_hook_btf_fixture(true, false, 24, 0);
        let foreign = aya::Btf::parse(&bytes, aya::Endianness::default()).unwrap();
        let cell = std::sync::OnceLock::new();
        let host = host_btf::cached(&cell, || Ok(bytes)).unwrap();
        assert_eq!(
            super::resolve_exec_release_target(host, &foreign)
                .unwrap_err()
                .to_string(),
            "instance hook BTF differs from cached host BTF"
        );
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
                "no exact exec-release hook: exec_mm_release must be void(task_struct *, mm_struct *) or exec_mmap must be int(linux_binprm *)"
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
    fn image_hook_requires_the_exact_exec_mmap_prototype() {
        for (header, gap) in [(24, 0), (32, 0), (24, 7), (32, 7)] {
            let bytes = exec_hook_btf_fixture(false, true, header, gap);
            assert!(
                super::exec_mmap_proto_is_exact(&bytes),
                "header {header} gap {gap}"
            );
        }
        assert!(!super::exec_mmap_proto_is_exact(&exec_hook_btf_fixture(
            true, false, 24, 0
        )));
        assert!(super::exec_mmap_proto_is_exact(&exec_hook_btf_fixture(
            true, true, 24, 0
        )));
        let bytes = exec_hook_btf_fixture(false, true, 24, 0);
        let mut wrong_return = bytes.clone();
        wrong_return[148..152].copy_from_slice(&0u32.to_le_bytes());
        assert!(!super::exec_mmap_proto_is_exact(&wrong_return));
        // The return INT itself (id 8 at type + 100: name, info, size,
        // data) must be 4-byte signed: a wider or unsigned spelling is
        // not exec_mmap's int.
        let mut wrong_size = bytes.clone();
        wrong_size[132..136].copy_from_slice(&8u32.to_le_bytes());
        assert!(!super::exec_mmap_proto_is_exact(&wrong_size));
        let mut wrong_sign = bytes.clone();
        wrong_sign[136..140].copy_from_slice(&0x0000_0020u32.to_le_bytes());
        assert!(!super::exec_mmap_proto_is_exact(&wrong_sign));
        let mut wrong_argument = bytes.clone();
        wrong_argument[156..160].copy_from_slice(&4u32.to_le_bytes());
        assert!(!super::exec_mmap_proto_is_exact(&wrong_argument));
        let mut wrong_arity = bytes.clone();
        wrong_arity[144..148].copy_from_slice(&((13u32 << 24) | 2).to_le_bytes());
        assert!(!super::exec_mmap_proto_is_exact(&wrong_arity));
        let type_len = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let type_end = 24 + type_len as usize;
        let mut duplicate = bytes.clone();
        duplicate.splice(
            type_end..type_end,
            bytes[type_end - 12..type_end].iter().copied(),
        );
        duplicate[12..16].copy_from_slice(&(type_len + 12).to_le_bytes());
        duplicate[16..20].copy_from_slice(&(type_len + 12).to_le_bytes());
        assert!(!super::exec_mmap_proto_is_exact(&duplicate));
        for truncated in 0..bytes.len() {
            assert!(
                !super::exec_mmap_proto_is_exact(&bytes[..truncated]),
                "truncated at {truncated}"
            );
        }
    }

    /// BTF blob carrying one `copy_vma` with the requested arity's exact
    /// shape: 5 legacy `(vmap, addr, len, pgoff, need_rmap_locks)`, 6 with
    /// `keep_source`, 7 with `anon_pgoff` too. Type ids are stable: 1
    /// STRUCT vm_area_struct, 2 PTR to it (the return), 3 PTR to 2
    /// (`vmap`), 4 INT `long unsigned int`, 5 INT `_Bool`, 6 TYPEDEF
    /// `bool`, 7 PTR to 6 (`need_rmap_locks`), 8 the FUNC_PROTO, 9 the
    /// FUNC. Ids 1-7 occupy 23 words (92 bytes), so the proto starts at
    /// header + 92 with the return at +8 and argument `i`'s type at
    /// +16+8i.
    fn copy_vma_btf_fixture(arity: u32, header_len: u32, string_gap: usize) -> Vec<u8> {
        let strings = b"\0vm_area_struct\0copy_vma\0long unsigned int\0bool\0_Bool\0";
        let args: &[u32] = match arity {
            5 => &[3, 4, 4, 4, 7],
            6 => &[3, 4, 4, 4, 7, 6],
            7 => &[3, 4, 4, 4, 4, 7, 6],
            _ => panic!("copy_vma fixture arity must be 5, 6 or 7"),
        };
        let words = [
            1,
            4 << 24,
            1, // STRUCT vm_area_struct
            0,
            2 << 24,
            1, // PTR to it (the return)
            0,
            2 << 24,
            2, // PTR to that (vmap)
            25,
            1 << 24,
            8,
            0x0000_0040, // INT long unsigned int
            48,
            1 << 24,
            1,
            0x0400_0008, // INT _Bool
            43,
            8 << 24,
            5, // TYPEDEF bool
            0,
            2 << 24,
            6, // PTR to bool (need_rmap_locks)
            0,
            (13 << 24) | arity,
            2, // FUNC_PROTO returning id 2
        ];
        let mut types: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        for arg in args {
            types.extend(0u32.to_le_bytes());
            types.extend(arg.to_le_bytes());
        }
        for word in [16u32, (12 << 24) | 1, 8] {
            types.extend(word.to_le_bytes());
        }
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

    fn resolve_copy_fixture(bytes: Vec<u8>) -> Result<super::CopyVmaTarget, String> {
        use super::super::host_btf;
        let cell = std::sync::OnceLock::new();
        let host = host_btf::cached(&cell, || Ok(bytes)).map_err(|error| error.to_string())?;
        super::resolve_copy_vma_target(host, host.btf()).map_err(|error| error.to_string())
    }

    #[test]
    fn copy_hook_requires_the_exact_legacy_prototype() {
        for (header, gap) in [(24, 0), (32, 0), (24, 7), (32, 7)] {
            let bytes = copy_vma_btf_fixture(5, header, gap);
            assert_eq!(
                super::copy_vma_proto_kind(&bytes),
                Some(super::CopyVmaTarget::Legacy),
                "header {header} gap {gap}"
            );
        }
        let bytes = copy_vma_btf_fixture(5, 24, 0);
        // Proto at header + 92: return +8, argument types +16+8i.
        let proto = 24 + 92;
        let mut wrong_return = bytes.clone();
        wrong_return[proto + 8..proto + 12].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(super::copy_vma_proto_kind(&wrong_return), None);
        let mut wrong_vmap = bytes.clone();
        wrong_vmap[proto + 16..proto + 20].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(super::copy_vma_proto_kind(&wrong_vmap), None);
        let mut wrong_offset = bytes.clone();
        wrong_offset[proto + 24..proto + 28].copy_from_slice(&6u32.to_le_bytes());
        assert_eq!(super::copy_vma_proto_kind(&wrong_offset), None);
        let mut wrong_locks = bytes.clone();
        wrong_locks[proto + 48..proto + 52].copy_from_slice(&6u32.to_le_bytes());
        assert_eq!(super::copy_vma_proto_kind(&wrong_locks), None);
        let mut wrong_arity = bytes.clone();
        wrong_arity[proto + 4..proto + 8].copy_from_slice(&((13u32 << 24) | 4).to_le_bytes());
        assert_eq!(super::copy_vma_proto_kind(&wrong_arity), None);
        let type_len = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        let type_end = 24 + type_len as usize;
        let mut duplicate = bytes.clone();
        duplicate.splice(
            type_end..type_end,
            bytes[type_end - 12..type_end].iter().copied(),
        );
        duplicate[12..16].copy_from_slice(&(type_len + 12).to_le_bytes());
        duplicate[16..20].copy_from_slice(&(type_len + 12).to_le_bytes());
        assert_eq!(super::copy_vma_proto_kind(&duplicate), None);
        for truncated in 0..bytes.len() {
            assert_eq!(
                super::copy_vma_proto_kind(&bytes[..truncated]),
                None,
                "truncated at {truncated}"
            );
        }
    }

    #[test]
    fn copy_hook_requires_the_exact_extended_prototype() {
        for arity in [6, 7] {
            for (header, gap) in [(24, 0), (32, 0), (24, 7), (32, 7)] {
                let bytes = copy_vma_btf_fixture(arity, header, gap);
                assert_eq!(
                    super::copy_vma_proto_kind(&bytes),
                    Some(super::CopyVmaTarget::FuncRet),
                    "arity {arity} header {header} gap {gap}"
                );
            }
        }
        // The 6-argument shape with a non-bool keep_source is neither shape.
        let six = copy_vma_btf_fixture(6, 24, 0);
        let proto = 24 + 92;
        let mut wrong_keep = six.clone();
        wrong_keep[proto + 56..proto + 60].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(super::copy_vma_proto_kind(&wrong_keep), None);
        // The 7-argument shape with a non-offset anon_pgoff is neither shape.
        let seven = copy_vma_btf_fixture(7, 24, 0);
        let mut wrong_anon = seven.clone();
        wrong_anon[proto + 48..proto + 52].copy_from_slice(&6u32.to_le_bytes());
        assert_eq!(super::copy_vma_proto_kind(&wrong_anon), None);
        // A void return is neither shape.
        let mut wrong_return = seven.clone();
        wrong_return[proto + 8..proto + 12].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(super::copy_vma_proto_kind(&wrong_return), None);
        // An 8-argument spelling is neither shape.
        let mut wrong_arity = seven.clone();
        wrong_arity[proto + 4..proto + 8].copy_from_slice(&((13u32 << 24) | 8).to_le_bytes());
        assert_eq!(super::copy_vma_proto_kind(&wrong_arity), None);
        for truncated in 0..six.len() {
            assert_eq!(
                super::copy_vma_proto_kind(&six[..truncated]),
                None,
                "six truncated at {truncated}"
            );
        }
        for truncated in 0..seven.len() {
            assert_eq!(
                super::copy_vma_proto_kind(&seven[..truncated]),
                None,
                "seven truncated at {truncated}"
            );
        }
    }

    #[test]
    fn copy_resolver_selects_legacy_on_five_arguments() {
        let bytes = copy_vma_btf_fixture(5, 24, 0);
        assert_eq!(
            resolve_copy_fixture(bytes).unwrap(),
            super::CopyVmaTarget::Legacy
        );
    }

    #[test]
    fn copy_resolver_selects_ret_on_six_or_seven_arguments() {
        for arity in [6, 7] {
            let bytes = copy_vma_btf_fixture(arity, 24, 0);
            assert_eq!(
                resolve_copy_fixture(bytes).unwrap(),
                super::CopyVmaTarget::FuncRet,
                "arity {arity}"
            );
        }
    }

    #[test]
    fn copy_resolver_refuses_without_either_shape() {
        let bytes = exec_hook_btf_fixture(false, false, 24, 0);
        assert_eq!(
            resolve_copy_fixture(bytes).unwrap_err(),
            "no exact copy_vma hook: copy_vma must be struct vm_area_struct *(vmap, addr, len, pgoff[, anon_pgoff], need_rmap_locks[, keep_source])"
        );
    }

    #[test]
    fn copy_resolver_rejects_foreign_parse() {
        use super::super::host_btf;
        let bytes = copy_vma_btf_fixture(5, 24, 0);
        let foreign = aya::Btf::parse(&bytes, aya::Endianness::default()).unwrap();
        let cell = std::sync::OnceLock::new();
        let host = host_btf::cached(&cell, || Ok(bytes)).unwrap();
        assert_eq!(
            super::resolve_copy_vma_target(host, &foreign)
                .unwrap_err()
                .to_string(),
            "instance hook BTF differs from cached host BTF"
        );
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
        super::marker_control_verdict(true, super::StaticRoots::Detailed, true, Some(control))
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
            super::marker_control_verdict(true, super::StaticRoots::Detailed, true, Some(control))
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
            super::marker_control_verdict(true, super::StaticRoots::Detailed, true, Some(control))
                .is_err()
        );
    }

    #[test]
    fn marker_control_detailed_absent_map_refuses() {
        // H8-D: a Detailed object without the map is a stale
        // build; the session refuses instead of running blind.
        assert!(
            super::marker_control_verdict(false, super::StaticRoots::Detailed, true, None).is_err()
        );
    }

    #[test]
    fn marker_control_counter_present_refuses() {
        // H8-D: counter bank objects must not carry the marker
        // map; a session over one refuses.
        assert!(
            super::marker_control_verdict(true, super::StaticRoots::CounterBanks, false, None)
                .is_err()
        );
    }

    #[test]
    fn marker_control_counter_absent_accepts() {
        // H8-D: the healthy counter twin of the refusal above.
        super::marker_control_verdict(false, super::StaticRoots::CounterBanks, false, None)
            .expect("counter banks without the map accept");
    }

    #[test]
    fn marker_control_release_off_absent_accepts() {
        super::marker_control_verdict(false, super::StaticRoots::Detailed, false, None)
            .expect("a release compiled without birth markers accepts their absence");
    }

    #[test]
    fn marker_control_release_off_stale_present_refuses() {
        let control = p11scope_ebpf_common::JournalAdmissionControl::default();
        assert!(
            super::marker_control_verdict(true, super::StaticRoots::Detailed, false, Some(control))
                .is_err(),
            "an old marker-enabled object must not satisfy the marker-off release policy"
        );
    }

    #[test]
    fn marker_control_enabled_missing_readback_refuses() {
        assert!(
            super::marker_control_verdict(true, super::StaticRoots::Detailed, true, None).is_err()
        );
    }

    #[test]
    fn marker_control_counter_forbids_map_when_detailed_enabled() {
        assert!(
            super::marker_control_verdict(true, super::StaticRoots::CounterBanks, true, None)
                .is_err()
        );
        super::marker_control_verdict(false, super::StaticRoots::CounterBanks, true, None)
            .expect("the Detailed selection cannot require a counter marker map");
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

    fn gzip_bytes(text: &str) -> Vec<u8> {
        use std::io::Write as _;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(text.as_bytes()).unwrap();
        encoder.finish().unwrap()
    }

    #[test]
    fn lto_proc_config_gz_off_allows_hooks() {
        let directory = tempfile::tempdir().unwrap();
        let boot = directory.path().join("config-9.9.9-test");
        let gz = directory.path().join("config.gz");
        let modules = directory.path().join("dotconfig");
        let kernel_release = directory.path().join("kernel.release");
        let utsrelease = directory.path().join("utsrelease.h");
        std::fs::write(&gz, gzip_bytes("CONFIG_LTO_NONE=y\n")).unwrap();
        assert_eq!(
            super::lto_refusal_for_release(
                "9.9.9-test",
                &boot,
                &gz,
                &modules,
                &kernel_release,
                &utsrelease,
            ),
            None,
        );
    }

    #[test]
    fn lto_proc_config_gz_on_refuses_hooks() {
        let directory = tempfile::tempdir().unwrap();
        let boot = directory.path().join("config-9.9.9-test");
        let gz = directory.path().join("config.gz");
        let modules = directory.path().join("dotconfig");
        let kernel_release = directory.path().join("kernel.release");
        let utsrelease = directory.path().join("utsrelease.h");
        std::fs::write(&gz, gzip_bytes("CONFIG_LTO_CLANG_THIN=y\n")).unwrap();
        let refusal = super::lto_refusal_for_release(
            "9.9.9-test",
            &boot,
            &gz,
            &modules,
            &kernel_release,
            &utsrelease,
        )
        .expect("LTO gzip config must refuse");
        assert!(refusal.contains("LTO kernel"), "{refusal}");
        assert!(refusal.contains("CONFIG_LTO_*"), "{refusal}");
    }

    #[test]
    fn lto_missing_all_sources_refuses_unverifiable() {
        let directory = tempfile::tempdir().unwrap();
        let boot = directory.path().join("config-9.9.9-test");
        let gz = directory.path().join("config.gz");
        let modules = directory.path().join("dotconfig");
        let kernel_release = directory.path().join("kernel.release");
        let utsrelease = directory.path().join("utsrelease.h");
        let refusal = super::lto_refusal_for_release(
            "9.9.9-test",
            &boot,
            &gz,
            &modules,
            &kernel_release,
            &utsrelease,
        )
        .expect("missing sources must refuse, never assume LTO-off");
        assert!(refusal.contains("unverifiable"), "{refusal}");
        assert!(refusal.contains("9.9.9-test"), "{refusal}");
    }

    #[test]
    fn lto_modules_config_mismatched_release_refuses() {
        let directory = tempfile::tempdir().unwrap();
        let boot = directory.path().join("config-9.9.9-test");
        let gz = directory.path().join("config.gz");
        let modules = directory.path().join("dotconfig");
        let kernel_release = directory.path().join("kernel.release");
        let utsrelease = directory.path().join("utsrelease.h");
        std::fs::write(&kernel_release, "8.8.8-other\n").unwrap();
        for contents in ["CONFIG_LTO_NONE=y\n", "CONFIG_LTO_CLANG_THIN=y\n"] {
            std::fs::write(&modules, contents).unwrap();
            let refusal = super::lto_refusal_for_release(
                "9.9.9-test",
                &boot,
                &gz,
                &modules,
                &kernel_release,
                &utsrelease,
            )
            .expect("mismatched build must refuse");
            assert!(
                refusal.contains("unverifiable"),
                "untrusted {contents:?} must not decide: {refusal}",
            );
        }
    }

    #[test]
    fn lto_modules_config_matching_release_decides() {
        let directory = tempfile::tempdir().unwrap();
        let boot = directory.path().join("config-9.9.9-test");
        let gz = directory.path().join("config.gz");
        let modules = directory.path().join("dotconfig");
        let kernel_release = directory.path().join("kernel.release");
        let utsrelease = directory.path().join("utsrelease.h");
        std::fs::write(&kernel_release, "9.9.9-test\n").unwrap();
        std::fs::write(&modules, "CONFIG_LTO_NONE=y\n").unwrap();
        assert_eq!(
            super::lto_refusal_for_release(
                "9.9.9-test",
                &boot,
                &gz,
                &modules,
                &kernel_release,
                &utsrelease,
            ),
            None,
        );
        std::fs::write(&modules, "CONFIG_LTO_CLANG_FULL=y\n").unwrap();
        let refusal = super::lto_refusal_for_release(
            "9.9.9-test",
            &boot,
            &gz,
            &modules,
            &kernel_release,
            &utsrelease,
        )
        .expect("matching LTO modules config must refuse");
        assert!(refusal.contains("LTO kernel"), "{refusal}");
    }

    #[test]
    fn lto_boot_config_decides_first() {
        let directory = tempfile::tempdir().unwrap();
        let boot = directory.path().join("config-9.9.9-test");
        let gz = directory.path().join("config.gz");
        let modules = directory.path().join("dotconfig");
        let kernel_release = directory.path().join("kernel.release");
        let utsrelease = directory.path().join("utsrelease.h");
        std::fs::write(&boot, "CONFIG_LTO_NONE=y\n").unwrap();
        assert_eq!(
            super::lto_refusal_for_release(
                "9.9.9-test",
                &boot,
                &gz,
                &modules,
                &kernel_release,
                &utsrelease,
            ),
            None,
        );
        std::fs::write(&boot, "CONFIG_LTO_CLANG_THIN=y\n").unwrap();
        let refusal = super::lto_refusal_for_release(
            "9.9.9-test",
            &boot,
            &gz,
            &modules,
            &kernel_release,
            &utsrelease,
        )
        .expect("LTO boot config must refuse");
        assert!(refusal.contains("LTO kernel"), "{refusal}");
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
