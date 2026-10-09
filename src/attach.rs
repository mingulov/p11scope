//! SPDX-License-Identifier: GPL-3.0-or-later
//! Loading and attaching. One selected entry uprobe + one uretprobe serve
//! each slot; the attach cookie carries the slot index.

use crate::discovery::hooks::HookAbi;
use crate::discovery::identity::{PinnedObjectId, PinnedObjects};
use crate::discovery::loader::LoaderContextId;
use crate::events;
use crate::plan::{AttachPlan, Slot};
use crate::run::OwnedChild;
use anyhow::{Context as _, Result, anyhow, bail};
use aya::maps::{Array, HashMap, Map, MapError, MapType, PerCpuArray, ProgramArray};
use aya::programs::raw_trace_point::RawTracePointLinkId;
use aya::programs::tp_btf::BtfTracePointLinkId;
use aya::programs::uprobe::{UProbeAttachLocation, UProbeAttachPoint, UProbeLinkId, UProbeScope};
use aya::programs::{BtfTracePoint, RawTracePoint, UProbe};
use aya::{Btf, Ebpf, EbpfLoader};
use p11scope_bpf_multi::{GroupHalt, attach_group, bisect_attach};
use p11scope_ebpf_common::{
    ARG_NONE, DISCOVERY_COUNTER_EXPORT_BOUNDED_READ_FAILURES,
    DISCOVERY_COUNTER_EXPORT_STATE_FAILURES, DISCOVERY_COUNTER_LOADER_HITS,
    DISCOVERY_COUNTER_LOADER_STATE_READ_FAILURES, DISCOVERY_COUNTER_RING_LOSS,
    EVIDENCE_ABI_REFUSALS, FLAG_POLICY_AGGREGATE, FLAG_POLICY_ALLOWLISTED,
    FLAG_POLICY_UNSAFE_UNVALIDATED_METADATA, FUNCTION_NAME_MAX_BYTES, FunctionNameKey,
    IMAGE_IDENTITY_TICKET_LIMIT, ImageIdentityControl, MAX_DESCRIPTORS, PAIR_CALLS_SECOND_SLOT,
    PAUSE_ARMED, PauseKey, ROOT_AFFILIATION_POSITIVE, RootAffiliationControl, SlotSemantics,
    TAIL_CALLS_INTERFACE_WORKER_SLOT, TAIL_CALLS_TEMPLATE_SECOND_SLOT, THREAD_OWNER_LIMIT,
    ThreadOwnerControl, attach_cookie,
};
use p11scope_manifest::elf::ElfAbi;
use pkcs11_types::mechanism_registry::MechanismRegistry;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io;
use std::mem::size_of_val;
use std::num::{NonZeroU32, NonZeroU64};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(crate) mod detailed_identity;

// I3 will consume this preparation capability; I2b installs no callers or links.
#[allow(dead_code)]
mod inventory;
pub(crate) use inventory::EXPECTED_INVENTORY_DISCOVERY_BYTES;
#[allow(unused_imports)]
pub(crate) use inventory::PreparedInventory;
pub(crate) use inventory::capture;
mod stop_gate;
pub(crate) use stop_gate::{StopGate, stop_gate_map_data, validate_stop_gate};
// Task 3 Stage A: the readers are consumed by the Task 6 native seam
// (`stage_native`, DR-T3A-1) and today by the privileged instance gates.
#[allow(dead_code)]
pub(crate) mod image_query;
#[allow(dead_code)]
mod instance;
#[allow(unused_imports)]
pub(crate) use instance::{
    HookStats, INSTANCE_PROGRAMS, InstanceMaps, InstanceTracking, WatchedFile,
};
mod cleanup_worker;
pub mod identity_iter;
pub use cleanup_worker::CleanupInterrupted;
pub(crate) use cleanup_worker::{CleanupWorker, DetachOrder, OwnedLink, drive_cleanup};
#[cfg(test)]
mod instance_tests;

#[cfg(test)]
mod continuation_guard_tests;
#[cfg(test)]
mod lifecycle_tests;

const BPF_F_RDONLY_PROG: u32 = 1 << 7;
const BPF_F_MMAPABLE: u32 = 1024;
#[derive(Debug)]
pub(crate) enum DynamicLoaderAttachFailure {
    KernelUnavailable(anyhow::Error),
    Provenance(anyhow::Error),
    Registry(anyhow::Error),
    ProgramMissing,
    ProgramType(anyhow::Error),
    InvalidPid,
}

impl std::fmt::Display for DynamicLoaderAttachFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KernelUnavailable(error)
            | Self::Provenance(error)
            | Self::Registry(error)
            | Self::ProgramType(error) => write!(formatter, "{error:#}"),
            Self::ProgramMissing => {
                formatter.write_str("program dl_debug_state missing from object")
            }
            Self::InvalidPid => formatter.write_str("dynamic loader PID must be non-zero"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct ExactMapMetadata {
    map_type: MapType,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    flags: u32,
}

const fn map_metadata(
    map_type: MapType,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    flags: u32,
) -> ExactMapMetadata {
    ExactMapMetadata {
        map_type,
        key_size,
        value_size,
        max_entries,
        flags,
    }
}

const BASE_POLICY_MAPS: [(&str, ExactMapMetadata); 8] = [
    (
        "CONFIG",
        map_metadata(MapType::Array, 4, 8, 2, BPF_F_RDONLY_PROG),
    ),
    (
        "PID_FILTER",
        map_metadata(MapType::Hash, 4, 8, 1_024, BPF_F_RDONLY_PROG),
    ),
    (
        "CGROUP_FILTER",
        map_metadata(MapType::CgroupArray, 4, 4, 1, 0),
    ),
    (
        "DESCRIPTORS",
        map_metadata(MapType::Array, 4, 18, MAX_DESCRIPTORS, BPF_F_RDONLY_PROG),
    ),
    (
        "ASYNC_FUNCTIONS",
        map_metadata(MapType::Hash, 32, 4, 128, BPF_F_RDONLY_PROG),
    ),
    (
        "MECH_SHAPE",
        map_metadata(
            MapType::Hash,
            8,
            4,
            p11scope_ebpf_common::MAX_MECH_SHAPES,
            BPF_F_RDONLY_PROG,
        ),
    ),
    (
        "TAIL_CALLS",
        map_metadata(MapType::ProgramArray, 4, 4, 2, 0),
    ),
    // Never populated and frozen before any program loads: the static
    // endpoint programs' kernel-stack opt-out. They load for uprobe-multi
    // under the multi backend, and a program array accepts one expected
    // attach type (CVE-2025-40123), so they cannot share TAIL_CALLS.
    (
        "STACK_GUARD",
        map_metadata(MapType::ProgramArray, 4, 4, 1, 0),
    ),
];
const FEATURE_POLICY_MAPS: [(&str, ExactMapMetadata); 2] = [
    (
        "ATTR_BOOL_BITS",
        map_metadata(MapType::Hash, 4, 4, 16, BPF_F_RDONLY_PROG),
    ),
    // The pair-to-second continuation array. It is populated after the
    // programs load, so it defers its freeze past publication; see
    // `publish_and_freeze_tail_calls`.
    (
        "PAIR_CALLS",
        map_metadata(MapType::ProgramArray, 4, 4, 1, 0),
    ),
];
const TAIL_POLICY_MAP: &str = "TAIL_CALLS";
const STACK_GUARD_MAP: &str = "STACK_GUARD";
const PAIR_POLICY_MAP: &str = "PAIR_CALLS";
const DEFAULT_PROGRAMS: [&str; 13] = [
    "p11_entry",
    "p11_return",
    "task_newtask",
    "dl_debug_state",
    "function_list_entry",
    "function_list_return",
    "interface_list_entry",
    "interface_list_return",
    "interface_list_worker",
    "interface_entry",
    "interface_return",
    "sched_process_exec",
    "sched_process_exit",
];
const UNSAFE_PROGRAMS: [&str; 5] = [
    "p11_entry_ia32",
    "p11_entry_template",
    "p11_entry_template_types",
    "p11_entry_template_pair",
    "p11_entry_template_second",
];

#[repr(C)]
#[derive(Default)]
struct BpfMapFreezeAttr {
    map_fd: u32,
}

pub(crate) fn policy_map_data<'a>(name: &str, map: &'a Map) -> Result<&'a aya::maps::MapData> {
    match map {
        Map::Array(map) | Map::HashMap(map) | Map::CgroupArray(map) | Map::ProgramArray(map) => {
            Ok(map)
        }
        other => bail!("refusing unexpected {name} policy map variant {other:?}"),
    }
}

fn validate_map_metadata(
    name: &str,
    data: &aya::maps::MapData,
    expected: ExactMapMetadata,
) -> Result<()> {
    compare_map_metadata(name, read_map_metadata(name, data)?, expected)
}

fn read_map_metadata(name: &str, data: &aya::maps::MapData) -> Result<ExactMapMetadata> {
    let info = data
        .info()
        .with_context(|| format!("reading {name} map info"))?;
    Ok(ExactMapMetadata {
        map_type: info.map_type()?,
        key_size: info.key_size(),
        value_size: info.value_size(),
        max_entries: info.max_entries(),
        flags: info.map_flags(),
    })
}

fn compare_map_metadata(
    name: &str,
    actual: ExactMapMetadata,
    expected: ExactMapMetadata,
) -> Result<()> {
    if actual != expected {
        bail!("{name} metadata {actual:?} differs from exact expected {expected:?}");
    }
    Ok(())
}

const IDENTITY_MAPS: [(&str, ExactMapMetadata); 6] = [
    (
        "TASK_COOKIE",
        map_metadata(MapType::TaskStorage, 4, 8, 0, 1),
    ),
    (
        "THREAD_OWNER",
        map_metadata(MapType::TaskStorage, 4, 544, 0, 1),
    ),
    (
        "ROOT_AFFILIATION",
        map_metadata(MapType::TaskStorage, 4, 8, 0, 1),
    ),
    ("COOKIE_CTL", map_metadata(MapType::Array, 4, 40, 1, 0)),
    ("OWNER_CTL", map_metadata(MapType::Array, 4, 56, 1, 0)),
    ("ROOT_CTL", map_metadata(MapType::Array, 4, 64, 1, 0)),
];

fn validate_identity_inventory<'a>(maps: impl Iterator<Item = (&'a str, bool)>) -> Result<()> {
    let mut storage = BTreeSet::new();
    for (name, unsupported) in maps {
        if unsupported {
            // Task 3 Stage A's process-epoch task storage is not an identity
            // map; the instance tracker validates its own metadata.
            if name == "PROC_EPOCH" {
                continue;
            }
            if !matches!(name, "TASK_COOKIE" | "THREAD_OWNER" | "ROOT_AFFILIATION") {
                bail!("unexpected Unsupported map {name}");
            }
            storage.insert(name);
        } else if matches!(name, "TASK_COOKIE" | "THREAD_OWNER" | "ROOT_AFFILIATION") {
            bail!("{name} must be an Unsupported task-storage map");
        }
    }
    if storage != BTreeSet::from(["ROOT_AFFILIATION", "TASK_COOKIE", "THREAD_OWNER"]) {
        bail!("missing required task-storage maps: {storage:?}");
    }
    Ok(())
}

fn identity_map_data<'a>(name: &str, map: &'a Map) -> Result<&'a aya::maps::MapData> {
    let (_, expected) = IDENTITY_MAPS
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .with_context(|| format!("unexpected identity map {name}"))?;
    let data = match (name, map) {
        ("TASK_COOKIE" | "THREAD_OWNER" | "ROOT_AFFILIATION", Map::Unsupported(data)) => data,
        ("COOKIE_CTL" | "OWNER_CTL" | "ROOT_CTL", Map::Array(data)) => data,
        _ => bail!("unexpected {name} identity map variant"),
    };
    validate_map_metadata(name, data, *expected)?;
    Ok(data)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdentityPreparation {
    WriteCookie,
    ReadCookie,
    WriteOwner,
    ReadOwner,
    WriteRoot,
    ReadRoot,
    SeedRoot,
    ReadSeed,
    Freeze(&'static str),
}

fn prepare_identity_with(
    owned: bool,
    mut operation: impl FnMut(IdentityPreparation) -> Result<()>,
) -> Result<()> {
    let controls = [
        IdentityPreparation::WriteCookie,
        IdentityPreparation::ReadCookie,
        IdentityPreparation::WriteOwner,
        IdentityPreparation::ReadOwner,
        IdentityPreparation::WriteRoot,
        IdentityPreparation::ReadRoot,
    ];
    for step in controls
        .into_iter()
        .chain(owned.then_some(IdentityPreparation::SeedRoot))
        .chain(owned.then_some(IdentityPreparation::ReadSeed))
        .chain([
            IdentityPreparation::Freeze("TASK_COOKIE"),
            IdentityPreparation::Freeze("THREAD_OWNER"),
            IdentityPreparation::Freeze("ROOT_AFFILIATION"),
            IdentityPreparation::Freeze("COOKIE_CTL"),
            IdentityPreparation::Freeze("OWNER_CTL"),
            IdentityPreparation::Freeze("ROOT_CTL"),
        ])
    {
        operation(step).with_context(|| format!("identity preparation {step:?}"))?;
    }
    Ok(())
}

fn cookie_control_fields(c: ImageIdentityControl) -> [u64; 5] {
    [
        c.limit,
        c.next_ticket,
        c.unavailable,
        c.create_failures,
        c.retry_exhausted,
    ]
}

fn owner_control_fields(c: ThreadOwnerControl) -> [u64; 7] {
    [
        c.limit,
        c.outstanding,
        c.poison,
        c.admission_failures,
        c.reclamation_failures,
        c.abandoned_start,
        c.abandoned_discovery,
    ]
}

fn root_control_fields(c: RootAffiliationControl) -> [u64; 8] {
    [
        c.affiliation_reserved,
        c.failure_flags,
        c.admission_failures,
        c.create_failures,
        c.malformed_failures,
        c.classifier_failures,
        c.delete_failures,
        c.refund_failures,
    ]
}

fn validate_root_control_readback(
    expected: RootAffiliationControl,
    actual: RootAffiliationControl,
) -> Result<()> {
    if root_control_fields(actual) != root_control_fields(expected) {
        bail!("ROOT_CTL exact readback differs from initial control");
    }
    Ok(())
}

fn initial_root_control(owned: bool) -> RootAffiliationControl {
    RootAffiliationControl {
        affiliation_reserved: u64::from(owned),
        ..Default::default()
    }
}

fn root_seed_authority<'fd>(
    scope: &Scope,
    child_pid: u32,
    original_pidfd: std::io::Result<BorrowedFd<'fd>>,
) -> Result<BorrowedFd<'fd>> {
    if !matches!(scope, Scope::Pid(pid) if *pid == child_pid) {
        bail!("owned root seed requires the exact retained child PID scope");
    }
    original_pidfd.context("borrowing original owned-child pidfd for root seed")
}

fn owner_limit_for_start(actual: ExactMapMetadata) -> Result<u64> {
    // These are the two existing START object shapes. Accepting the small
    // shape here does not relax the normal frozen object inventory elsewhere.
    if !matches!(actual.max_entries, 16_384 | 1) {
        bail!("unsupported START capacity {}", actual.max_entries);
    }
    compare_map_metadata(
        "START",
        actual,
        map_metadata(
            MapType::Hash,
            std::mem::size_of::<p11scope_ebpf_common::StartKey>() as u32,
            std::mem::size_of::<p11scope_ebpf_common::CallStart>() as u32,
            actual.max_entries,
            0,
        ),
    )?;
    let overhead = THREAD_OWNER_LIMIT
        .checked_sub(u64::from(p11scope_ebpf_common::START_ENTRIES))
        .context("invalid common thread-owner reservation overhead")?;
    u64::from(actual.max_entries)
        .checked_add(overhead)
        .context("thread-owner reservation limit overflow")
}

#[cfg(test)]
thread_local! {
    /// Test-only: a privileged test seeds sticky owner poison into the
    /// published OWNER_CTL image (before freeze, exact readback included) to
    /// prove a halted capture is disclosed end to end. Per thread, so it
    /// cannot leak into concurrently starting sessions.
    pub(crate) static TEST_OWNER_POISON: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Always zero outside tests: production never publishes poison.
fn test_seeded_owner_poison() -> u64 {
    #[cfg(test)]
    {
        TEST_OWNER_POISON.with(std::cell::Cell::get)
    }
    #[cfg(not(test))]
    {
        0
    }
}

fn prepare_identity(ebpf: &mut Ebpf, scope: &Scope, child: Option<&OwnedChild>) -> Result<()> {
    validate_identity_inventory(
        ebpf.maps()
            .map(|(name, map)| (name, matches!(map, Map::Unsupported(_)))),
    )?;
    for (name, _) in IDENTITY_MAPS {
        identity_map_data(
            name,
            ebpf.map(name)
                .with_context(|| format!("missing {name} map"))?,
        )?;
    }
    let cookie = ImageIdentityControl {
        limit: IMAGE_IDENTITY_TICKET_LIMIT,
        ..Default::default()
    };
    let owner = ThreadOwnerControl {
        limit: {
            let map = ebpf.map("START").context("START map")?;
            let Map::HashMap(data) = map else {
                bail!("unexpected START map variant");
            };
            owner_limit_for_start(read_map_metadata("START", data)?)?
        },
        poison: test_seeded_owner_poison(),
        ..Default::default()
    };
    let root_pidfd = child
        .map(|child| root_seed_authority(scope, child.pid(), child.pin().pidfd()))
        .transpose()?;
    let root = initial_root_control(root_pidfd.is_some());
    prepare_identity_with(root_pidfd.is_some(), |step| {
        match step {
            IdentityPreparation::WriteCookie => {
                let mut control: Array<_, ImageIdentityControl> =
                    Array::try_from(ebpf.map_mut("COOKIE_CTL").context("COOKIE_CTL map")?)?;
                control.set(0, cookie, 0)?;
            }
            IdentityPreparation::ReadCookie => {
                let control: Array<_, ImageIdentityControl> =
                    Array::try_from(ebpf.map("COOKIE_CTL").context("COOKIE_CTL map")?)?;
                if cookie_control_fields(control.get(&0, 0)?) != cookie_control_fields(cookie) {
                    bail!("COOKIE_CTL exact readback differs from initial control");
                }
            }
            IdentityPreparation::WriteOwner => {
                let mut control: Array<_, ThreadOwnerControl> =
                    Array::try_from(ebpf.map_mut("OWNER_CTL").context("OWNER_CTL map")?)?;
                control.set(0, owner, 0)?;
            }
            IdentityPreparation::ReadOwner => {
                let control: Array<_, ThreadOwnerControl> =
                    Array::try_from(ebpf.map("OWNER_CTL").context("OWNER_CTL map")?)?;
                if owner_control_fields(control.get(&0, 0)?) != owner_control_fields(owner) {
                    bail!("OWNER_CTL exact readback differs from initial control");
                }
            }
            IdentityPreparation::WriteRoot => {
                let mut control: Array<_, RootAffiliationControl> =
                    Array::try_from(ebpf.map_mut("ROOT_CTL").context("ROOT_CTL map")?)?;
                control.set(0, root, 0)?;
            }
            IdentityPreparation::ReadRoot => {
                let control: Array<_, RootAffiliationControl> =
                    Array::try_from(ebpf.map("ROOT_CTL").context("ROOT_CTL map")?)?;
                validate_root_control_readback(root, control.get(&0, 0)?)?;
            }
            IdentityPreparation::SeedRoot => {
                let pidfd = root_pidfd.context("owned root seed lost its original pidfd")?;
                let map = ebpf
                    .map("ROOT_AFFILIATION")
                    .context("ROOT_AFFILIATION map")?;
                let map_fd = identity_map_data("ROOT_AFFILIATION", map)?.fd().as_fd();
                root_affiliation_element(map_fd, pidfd, RootElementOperation::Seed)?;
            }
            IdentityPreparation::ReadSeed => {
                let pidfd = root_pidfd.context("owned root readback lost its original pidfd")?;
                let map = ebpf
                    .map("ROOT_AFFILIATION")
                    .context("ROOT_AFFILIATION map")?;
                let map_fd = identity_map_data("ROOT_AFFILIATION", map)?.fd().as_fd();
                root_affiliation_element(map_fd, pidfd, RootElementOperation::Read)?;
            }
            IdentityPreparation::Freeze(name) => {
                freeze_map(name, ebpf.map(name).with_context(|| format!("{name} map"))?)?
            }
        }
        Ok(())
    })
}

/// Prepares identity maps for the unowned, PID-scoped ABI qualification example.
///
/// This grants no owned-child root-seed authority; production capture retains
/// that authority internally.
#[doc(hidden)]
pub fn prepare_qualification_identity(ebpf: &mut Ebpf, pid: NonZeroU32) -> Result<()> {
    prepare_identity(ebpf, &Scope::Pid(pid.get()), None)
}

fn validate_policy_map(ebpf: &Ebpf, name: &str, expected: ExactMapMetadata) -> Result<()> {
    let map = ebpf.map(name).with_context(|| format!("{name} map"))?;
    validate_map_metadata(name, policy_map_data(name, map)?, expected)
}

fn validate_policy_maps(ebpf: &Ebpf, object_has_unsafe: bool) -> Result<()> {
    for (name, expected) in BASE_POLICY_MAPS {
        validate_policy_map(ebpf, name, expected)?;
    }
    for (name, expected) in FEATURE_POLICY_MAPS {
        if object_has_unsafe {
            validate_policy_map(ebpf, name, expected)?;
        } else if ebpf.map(name).is_some() {
            bail!("{name} must be absent from the default eBPF object");
        }
    }
    Ok(())
}

fn freeze_map(name: &str, map: &Map) -> Result<()> {
    let data = if IDENTITY_MAPS
        .iter()
        .any(|(candidate, _)| *candidate == name)
    {
        identity_map_data(name, map)
    } else {
        policy_map_data(name, map)
    }
    .with_context(|| format!("refusing to freeze unexpected {name} map variant"))?;
    let attr = BpfMapFreezeAttr {
        map_fd: data.fd().as_fd().as_raw_fd() as u32,
    };
    // SAFETY: `attr` is the complete zero-reserved BPF_MAP_FREEZE command
    // payload and its borrowed storage remains live for the syscall.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            22u32,
            &attr as *const BpfMapFreezeAttr,
            size_of_val(&attr),
        )
    };
    if rc == -1 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("freezing {name}"));
    }
    Ok(())
}

#[repr(C)]
#[derive(Default)]
struct BpfMapElementAttr {
    map_fd: u32,
    _pad: u32,
    key: u64,
    value: u64,
    flags: u64,
}

const BPF_MAP_LOOKUP_ELEM: u32 = 1;
const BPF_MAP_UPDATE_ELEM: u32 = 2;
const BPF_NOEXIST: u64 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootElementOperation {
    Seed,
    Read,
}

fn root_affiliation_element_with(
    map_fd: BorrowedFd<'_>,
    pidfd: BorrowedFd<'_>,
    operation: RootElementOperation,
    mut syscall: impl FnMut(u32, &BpfMapElementAttr, usize) -> std::io::Result<()>,
) -> Result<()> {
    let key = pidfd.as_raw_fd();
    match operation {
        RootElementOperation::Seed => {
            let value = ROOT_AFFILIATION_POSITIVE;
            let attr = BpfMapElementAttr {
                map_fd: map_fd.as_raw_fd() as u32,
                key: (&key as *const i32) as u64,
                value: (&value as *const u64) as u64,
                flags: BPF_NOEXIST,
                ..BpfMapElementAttr::default()
            };
            syscall(BPF_MAP_UPDATE_ELEM, &attr, size_of_val(&attr))
                .context("seeding ROOT_AFFILIATION through original pidfd with BPF_NOEXIST")?;
        }
        RootElementOperation::Read => {
            let mut readback = 0u64;
            pidfd_task_storage_lookup_with(map_fd, pidfd, &mut readback, &mut syscall)
                .context("reading back ROOT_AFFILIATION through original pidfd")?;
            if readback != ROOT_AFFILIATION_POSITIVE {
                bail!(
                    "ROOT_AFFILIATION readback {readback} differs from expected positive value {ROOT_AFFILIATION_POSITIVE}"
                );
            }
        }
    }
    Ok(())
}

/// One u64 task-storage element looked up through a pidfd key (flags 0):
/// the kernel resolves the pidfd to its current task, so the answer is for
/// the process generation that descriptor retains. Shared by the
/// ROOT_AFFILIATION readback and the capture facade's TASK_COOKIE query.
/// ENOENT (no element) is returned unchanged for the caller to classify.
fn pidfd_task_storage_lookup_with(
    map_fd: BorrowedFd<'_>,
    pidfd: BorrowedFd<'_>,
    value: &mut u64,
    mut syscall: impl FnMut(u32, &BpfMapElementAttr, usize) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let key = pidfd.as_raw_fd();
    let attr = BpfMapElementAttr {
        map_fd: map_fd.as_raw_fd() as u32,
        key: (&key as *const i32) as u64,
        value: (value as *mut u64) as u64,
        ..BpfMapElementAttr::default()
    };
    syscall(BPF_MAP_LOOKUP_ELEM, &attr, size_of_val(&attr))
}

/// The real map-element syscall behind the `_with` seams.
fn bpf_map_element_syscall(
    command: u32,
    attr: &BpfMapElementAttr,
    size: usize,
) -> std::io::Result<()> {
    // SAFETY: the typed key/value and complete zero-reserved attr remain live
    // for this exact map-element syscall invocation.
    let rc = unsafe { libc::syscall(libc::SYS_bpf, command, attr, size) };
    if rc == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn root_affiliation_element(
    map_fd: BorrowedFd<'_>,
    pidfd: BorrowedFd<'_>,
    operation: RootElementOperation,
) -> Result<()> {
    root_affiliation_element_with(map_fd, pidfd, operation, bpf_map_element_syscall)
}

fn program_array_lookup_result(
    name: &str,
    key: u32,
    value: u32,
    result: std::io::Result<()>,
) -> Result<Option<u32>> {
    match result {
        Ok(()) => Ok(Some(value)),
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading back {name}[{key}]")),
    }
}

fn program_array_id(name: &str, map: &Map, key: u32) -> Result<Option<u32>> {
    let data = match map {
        Map::ProgramArray(map) => map,
        other => bail!("refusing to read unexpected {name} map variant {other:?}"),
    };
    let mut value = 0u32;
    let attr = BpfMapElementAttr {
        map_fd: data.fd().as_fd().as_raw_fd() as u32,
        key: (&key as *const u32) as u64,
        value: (&mut value as *mut u32) as u64,
        ..BpfMapElementAttr::default()
    };
    // SAFETY: `key`, `value`, and `attr` stay live for BPF_MAP_LOOKUP_ELEM;
    // the map metadata has already pinned their exact u32 sizes.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            1u32,
            &attr as *const BpfMapElementAttr,
            size_of_val(&attr),
        )
    };
    let result = if rc == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    };
    program_array_lookup_result(name, key, value, result)
}

/// Which processes the capture covers. Scope is always explicit.
#[derive(Debug, Clone)]
pub enum Scope {
    Pid(u32),
    /// Native cgroup-array membership matches this cgroup and descendants.
    Cgroup {
        id: u64,
        path: PathBuf,
        dir: Arc<File>,
    },
    /// Whole-machine capture: every process passes the BPF scope gate. No
    /// PID list and no cgroup descriptor are published; userspace discovery
    /// sweeps `/proc` under the same scan cap as cgroup scope.
    System,
}

impl Scope {
    /// Stable scope kind for the JSON `capture` section (`pid`, `cgroup`,
    /// `system`). No PID number or cgroup path is published — identity stays
    /// in diagnostics, never in the report.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Pid(_) => "pid",
            Self::Cgroup { .. } => "cgroup",
            Self::System => "system",
        }
    }
}

/// Immutable capture behavior selected by userspace before attachment.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CapturePolicy {
    Allowlisted,
    UnsafeUnvalidatedMetadata,
    AggregateOnly,
}

impl CapturePolicy {
    pub fn from_cli(mode: &str, unsafe_requested: bool, unsafe_compiled: bool) -> Result<Self> {
        match mode {
            "metrics" if unsafe_requested => {
                bail!("--unsafe-unvalidated-metadata is not available in metrics mode")
            }
            "metrics" => Ok(Self::AggregateOnly),
            "profile" | "trace" if unsafe_requested && !unsafe_compiled => bail!(
                "--unsafe-unvalidated-metadata requires a build with the unsafe-unvalidated-metadata Cargo feature"
            ),
            "profile" | "trace" if unsafe_requested => Ok(Self::UnsafeUnvalidatedMetadata),
            "profile" | "trace" => Ok(Self::Allowlisted),
            _ => bail!("unknown capture mode {mode:?}"),
        }
    }

    pub const fn config_bit(self) -> u64 {
        match self {
            Self::Allowlisted => FLAG_POLICY_ALLOWLISTED,
            Self::UnsafeUnvalidatedMetadata => FLAG_POLICY_UNSAFE_UNVALIDATED_METADATA,
            Self::AggregateOnly => FLAG_POLICY_AGGREGATE,
        }
    }

    pub const fn privacy_mode(self) -> &'static str {
        match self {
            Self::Allowlisted => "allowlisted",
            Self::UnsafeUnvalidatedMetadata => "unsafe-unvalidated-metadata",
            Self::AggregateOnly => "aggregate-only",
        }
    }

    pub const fn uses_events(self) -> bool {
        !matches!(self, Self::AggregateOnly)
    }

    /// Whether the policy can consume load-instance continuity (Task 3 Stage
    /// A): profile/trace join per-call records to load instances, so their
    /// sessions attach the three mapping hooks; metrics (aggregate-only)
    /// never drains a per-call record and skips them. The split is Task 1d's
    /// overhead gate: the hooks cost ~280-415 ns per mapping event
    /// system-wide (plus the fentry trampoline), so a policy that cannot use
    /// them must not pay. Explicit match, not `uses_events()`: a future
    /// variant must decide here at compile time.
    pub const fn wants_instance_hooks(self) -> bool {
        match self {
            Self::Allowlisted | Self::UnsafeUnvalidatedMetadata => true,
            Self::AggregateOnly => false,
        }
    }

    pub const fn uses_unsafe_decoders(self) -> bool {
        matches!(self, Self::UnsafeUnvalidatedMetadata)
    }
}

/// Resolved static attach backend: one multi link per (attach path, entry
/// program) group, or today's one-per-endpoint singles. Dynamic
/// loader/export probes stay singles under both backends.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AttachBackend {
    Multi,
    Singles,
}

/// Operator's `--attach-backend` request: `auto` follows a functional
/// probe (never the kernel version; see [`select_session_backend`]),
/// `multi`/`singles` force one.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub enum BackendSelection {
    #[default]
    Auto,
    Multi,
    Singles,
}

impl BackendSelection {
    pub fn from_cli(value: &str) -> Result<Self> {
        match value {
            "auto" => Ok(Self::Auto),
            "multi" => Ok(Self::Multi),
            "singles" => Ok(Self::Singles),
            _ => bail!("--attach-backend: invalid value {value:?} (expected auto|multi|singles)"),
        }
    }
}

/// A multi link attempt proved the kernel lacks multi support. The
/// session retries on singles (auto) or surfaces this as a hard error
/// (forced multi).
#[derive(Debug)]
pub(crate) struct BackendFallbackRequired {
    error: io::Error,
}

impl BackendFallbackRequired {
    fn unsupported(error: io::Error) -> Self {
        Self { error }
    }
}

impl std::fmt::Display for BackendFallbackRequired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "multi-uprobe unsupported by the running kernel: {}",
            self.error
        )
    }
}

impl std::error::Error for BackendFallbackRequired {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Release floor the doctor's diagnostics still quote: `uprobe_multi`
/// landed in 6.6 and the session once attempted it only on 6.9+. The
/// capture no longer reads it: [`select_session_backend`] decides by
/// functional probes (owner directive "kernel tiers", DR-CLASSIC-PID0).
pub(crate) const MULTI_KERNEL_FLOOR: (u32, u32) = (6, 9);

/// Pure predicate over a `/proc/sys/kernel/osrelease` release string: at
/// or above [`MULTI_KERNEL_FLOOR`]; an unparseable release is below it.
/// Doctor diagnostics only.
pub(crate) fn multi_allowed_on(release: &str) -> bool {
    crate::doctor::parse_major_minor(release).is_some_and(|version| version >= MULTI_KERNEL_FLOOR)
}

/// The running release against [`MULTI_KERNEL_FLOOR`], for the doctor's
/// `perf_event_paranoid` row hint only (it may run unprivileged, where no
/// functional probe can answer). The capture never consults it.
pub(crate) fn kernel_supports_multi() -> bool {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|release| multi_allowed_on(release.trim()))
        .unwrap_or(false)
}

/// Whether the running kernel's uprobe_multi pid filter covers every
/// thread of the named process, proven once per run by a functional probe
/// (`p11scope_bpf_multi::probe_pid_filter_hits`: a counting link with
/// `pid` = self, called from this thread and a fresh sibling, which must
/// both fire, and from a forked child process, which must not). A version
/// check would be wrong both ways: 6.6-6.9 shipped a thread-exact filter
/// (`current != link->task`), fixed by "bpf: fix multi-uprobe PID
/// filtering logic" in 6.10 and backported to 6.9.12 and 6.6.y, and
/// distribution kernels carry their own backports. Fixed kernels bind the
/// link to the target's task (`get_pid_task(..., PIDTYPE_TGID)`, then
/// `current->mm != link->task->mm`, `same_thread_group` from 6.12), so a
/// later process reusing the PID never fires it.
pub(crate) fn kernel_multi_pid_filter() -> std::result::Result<(), String> {
    static VERDICT: std::sync::OnceLock<std::result::Result<(), String>> =
        std::sync::OnceLock::new();
    VERDICT
        .get_or_init(|| match p11scope_bpf_multi::probe_pid_filter_hits() {
            Ok(hits) if hits.proves_pid_scope() => Ok(()),
            Ok(hits) if hits.other_process > 0 => Err(format!(
                "the kernel uprobe-multi pid filter also fired for another process \
                 ({} hit(s)): it does not exclude other processes",
                hits.other_process
            )),
            Ok(hits) => Err(format!(
                "the kernel uprobe-multi pid filter fired for {} of 2 threads of the \
                 named process",
                hits.own_threads
            )),
            Err(error) => Err(format!("the uprobe-multi pid filter probe failed: {error}")),
        })
        .clone()
}

/// The classic session's static attach backend, as selected before any
/// object loads (DR-CLASSIC-PID0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SessionBackend {
    pub backend: AttachBackend,
    /// Why `auto` runs per-offset links (a failed probe), else `None`.
    pub fallback: Option<String>,
}

/// The production functional probe: a mapless no-op program linked as a
/// one-offset uprobe-multi probe at the observer's own anchor (the doctor
/// row's self-link), dropped at once. It never fires a capture program.
pub(crate) fn multi_functional_probe() -> std::result::Result<(), String> {
    // The anchor error names local paths (libc, the observer's own
    // executable); the published reason stays pathless (the doctor's row
    // keeps the detail).
    let (path, offset) = crate::doctor::self_probe_anchor()
        .map_err(|_| "the self-probe anchor is unavailable".to_string())?;
    let program = p11scope_bpf_multi::prog_load_scratch_multi()
        .map_err(|error| format!("loading the scratch uprobe-multi program: {error}"))?;
    p11scope_bpf_multi::attach_group(
        program.as_raw_fd(),
        std::process::id(),
        &path,
        &[offset],
        &[1],
        false,
    )
    .map(drop)
    .map_err(|error| format!("linking the scratch uprobe-multi probe: {error}"))
}

/// First backend attempted for a classic session, decided by functional
/// probes, never by the kernel version (owner directive "kernel tiers").
///
/// - `singles`: per-offset links, never probed.
/// - PID scope (`pid_scope`): uprobe-multi only where `pid_probe` proves
///   the kernel pid filter covers every thread of the named process and
///   no other process (`kernel_multi_pid_filter`); the links then name the
///   target, so no other process mapping the provider carries a
///   breakpoint, and the in-BPF PID guard stays as a second check. Where
///   it is not proven, `auto` runs per-offset links bound to the target
///   with the probe's reason, and forced `multi` is refused: a PID-scoped
///   uprobe-multi link never names pid 0.
/// - Cgroup and system scope: links name pid 0 and the in-BPF scope gate
///   decides. `auto` takes uprobe-multi where `multi_probe` links one,
///   else per-offset links with its reason; forced `multi` attempts
///   regardless.
///
/// An auto uprobe-multi session that the kernel still refuses is rebuilt
/// on per-offset links at session granularity (see [`Session::start`]).
pub(crate) fn select_session_backend(
    selection: BackendSelection,
    pid_scope: bool,
    multi_probe: impl FnOnce() -> std::result::Result<(), String>,
    pid_probe: impl FnOnce() -> std::result::Result<(), String>,
) -> Result<SessionBackend> {
    let chosen = |backend, fallback| SessionBackend { backend, fallback };
    Ok(match (selection, pid_scope) {
        (BackendSelection::Singles, _) => chosen(AttachBackend::Singles, None),
        (BackendSelection::Multi, false) => chosen(AttachBackend::Multi, None),
        (BackendSelection::Multi, true) => {
            pid_probe().map_err(|reason| {
                anyhow!(
                    "--attach-backend multi under --pid needs a proven kernel uprobe-multi pid \
                     filter (links never name pid 0): {reason}"
                )
            })?;
            chosen(AttachBackend::Multi, None)
        }
        (BackendSelection::Auto, true) => match pid_probe() {
            Ok(()) => chosen(AttachBackend::Multi, None),
            Err(reason) => chosen(
                AttachBackend::Singles,
                Some(format!(
                    "uprobe-multi under --pid needs a proven kernel pid filter: {reason}"
                )),
            ),
        },
        (BackendSelection::Auto, false) => match multi_probe() {
            Ok(()) => chosen(AttachBackend::Multi, None),
            Err(reason) => chosen(
                AttachBackend::Singles,
                Some(format!(
                    "the uprobe-multi functional probe failed: {reason}"
                )),
            ),
        },
    })
}

/// The static endpoint twins (every program `static_probe_side` routes)
/// load with `expected_attach_type=48` under multi so one program can own
/// the group's return/entry links, and the template-second continuation loads
/// with its caller's attach type (multi under multi, plain under singles):
/// it is the tail-call target the pair installs into PAIR_CALLS, and since
/// CVE-2025-40123 a program array accepts only programs with its owner's
/// expected attach type. The continuation is never attached
/// (`static_probe_side` stays `None` for it); everything else (dynamic,
/// diagnostic, lifecycle, the other tail-call target) loads plain under both
/// backends.
pub(crate) fn loads_with_multi_flag(backend: AttachBackend, program: &str) -> bool {
    backend == AttachBackend::Multi
        && (static_probe_side(program).is_some() || program == MULTI_LOADED_TAIL_TARGET)
}

/// The one tail-call target that loads for uprobe-multi: never attached, only
/// installed into PAIR_CALLS.
const MULTI_LOADED_TAIL_TARGET: &str = "p11_entry_template_second";

fn process_creation_capture_enabled(scope: &Scope, policy: CapturePolicy) -> bool {
    let _ = (scope, policy);
    true
}

pub(crate) struct OwnedPauseGeneration {
    tgid: u32,
    generation: NonZeroU64,
}

impl OwnedPauseGeneration {
    #[allow(dead_code)] // Task 8 invokes the reviewed owned-run Engine route.
    pub(crate) fn from_owned_child(child: &OwnedChild) -> Self {
        Self {
            tgid: child.pid(),
            generation: child.generation(),
        }
    }
}

fn pause_key_for(
    scope: &Scope,
    capability: Option<&OwnedPauseGeneration>,
) -> Result<Option<PauseKey>> {
    match (scope, capability) {
        (_, None) => Ok(None),
        (Scope::Pid(pid), Some(capability)) if *pid == capability.tgid => Ok(Some(PauseKey {
            tgid: capability.tgid,
            pad: 0,
            generation_token: capability.generation.get(),
        })),
        (Scope::Pid(pid), Some(capability)) => bail!(
            "owned pause generation PID {} does not match selected PID {pid}",
            capability.tgid
        ),
        (Scope::Cgroup { .. } | Scope::System, Some(_)) => {
            bail!("owned pause generation requires PID scope")
        }
    }
}

/// Issued only after the original-pidfd seed, readback and all map freezes.
/// Sharing this exact object proves which original owner was seeded; descriptor
/// and PID numbers are not used to manufacture or compare acknowledgements.
pub(crate) struct RootSeed {
    pin: std::sync::Arc<crate::process::PidPin>,
    domain: events::EventsDomain,
}
impl RootSeed {
    pub(crate) fn acknowledges(&self, child: &OwnedChild) -> bool {
        std::sync::Arc::ptr_eq(&self.pin, &child.seed_pin())
    }
    pub(crate) fn domain(&self) -> &events::EventsDomain {
        &self.domain
    }
    #[cfg(test)]
    pub(crate) fn test_acknowledgement(child: &OwnedChild, domain: events::EventsDomain) -> Self {
        Self {
            pin: child.seed_pin(),
            domain,
        }
    }
}

/// An opaque capture session. Public callers can inspect session evidence:
///
/// ```
/// use p11scope::attach::Session;
/// fn evidence(session: &Session) -> (usize, usize) {
///     (session.attached_probes(), session.attach_failures().len())
/// }
/// ```
///
/// Session state cannot be manufactured by external callers:
///
/// ```compile_fail
/// use p11scope::attach::Session;
/// #[allow(unreachable_code)]
/// fn construct() -> Session {
///     Session {
///         ebpf: panic!("compile-only placeholder"),
///         events_domain: panic!("compile-only placeholder"),
///         events_consumer: panic!("compile-only placeholder"),
///         discovery_domain: panic!("compile-only placeholder"),
///         discovery_consumer: panic!("compile-only placeholder"),
///         root_seed: panic!("compile-only placeholder"),
///         attach_failures: panic!("compile-only placeholder"),
///         detach_failures: panic!("compile-only placeholder"),
///         producers_detached: panic!("compile-only placeholder"),
///         detach_wall_ms: panic!("compile-only placeholder"),
///         successful_static: panic!("compile-only placeholder"),
///         dynamic_attach_evidence: panic!("compile-only placeholder"),
///         policy: panic!("compile-only placeholder"),
///         uprobe_scope: panic!("compile-only placeholder"),
///         pause_key: panic!("compile-only placeholder"),
///         lifecycle_tracking_unavailable: panic!("compile-only placeholder"),
///         process_creation_tracking_unavailable: panic!("compile-only placeholder"),
///         retained_static: panic!("compile-only placeholder"),
///         links: panic!("compile-only placeholder"),
///     }
/// }
/// ```
///
/// Mutable access to the BPF object is reserved to the capture implementation:
///
/// ```compile_fail
/// use p11scope::attach::Session;
/// fn mutate(session: &mut Session) -> &mut aya::Ebpf {
///     &mut session.ebpf
/// }
/// ```
///
/// Owned-root and pause capabilities are private to the capture implementation:
///
/// ```compile_fail
/// use p11scope::attach::RootSeed;
/// ```
///
/// ```compile_fail
/// use p11scope::attach::OwnedPauseGeneration;
/// ```
pub struct Session {
    /// Mmap of the STOP_GATE cell. Declared first so the mapping unmaps
    /// before the map FDs owned by `ebpf` close.
    stop_gate: StopGate,
    image_coverage: image_query::CoverageControl,
    image_query: Option<image_query::ImageQueryOwner>,
    pub(crate) ebpf: Ebpf,
    events_domain: events::EventsDomain,
    /// The session's single retained `EVENTS` consumer, built once from
    /// the retained domain descriptor on first drain and reused by every
    /// later poll. It owns a duplicated descriptor plus its mappings, so
    /// it never borrows `ebpf`; `None` until the first drain keeps
    /// metrics-mode sessions (which never drain) free of reader setup.
    events_consumer: Option<events::OwnedDrain>,
    discovery_domain: events::DiscoveryDomain,
    trace_coverage: Option<detailed_identity::TraceCoverage>,
    trace_proof: Option<detailed_identity::ProofSession>,
    /// One cursor over DISCOVERY for all dequeues. The owned mapping is
    /// created lazily and then lives until this Session is dropped.
    discovery_consumer: Option<events::OwnedDiscoveryDrain>,
    /// Items moved off the DISCOVERY ring but not yet dequeued (RB-2).
    discovery_staged: DiscoveryStage,
    root_seed: Option<RootSeed>,
    attach_failures: Vec<(u32, String)>,
    detach_failures: Vec<String>,
    /// Every producer detach succeeded without retained ownership uncertainty.
    /// This permits the existing best-effort terminal poll, not callback
    /// settlement or exact root retirement.
    producers_detached: bool,
    /// Wall time the producer detach took, in whole milliseconds; zero
    /// until `detach_producers` runs.
    detach_wall_ms: u64,
    /// CLOCK_MONOTONIC reading when the session became fully attached
    /// (T2, G-14): `None` until `note_attach_complete` runs at loop entry,
    /// so a session that never reached its loop reports no attach time —
    /// never 0, never an estimate.
    attach_mono_ns: Option<u64>,
    successful_static: BTreeSet<StaticEndpoint>,
    dynamic_attach_evidence: DynamicAttachEvidence,
    policy: CapturePolicy,
    /// Load-time backend: static endpoint twins load with attach type 48
    /// under multi, so the attach path must match the load decision.
    backend: AttachBackend,
    /// The operator's `--attach-backend` and why an `auto` session runs
    /// per-offset links (DR-CLASSIC-PID0).
    selection: BackendSelection,
    backend_fallback: Option<String>,
    uprobe_scope: UProbeScope,
    #[allow(dead_code)] // Task 8 drives the Task 7 pause coordinator.
    pause_key: Option<PauseKey>,
    lifecycle_tracking_unavailable: Option<String>,
    process_creation_tracking_unavailable: Option<String>,
    /// Exact reattach facts per statically attached slot, retained so a
    /// multi-group rebuild can reattach surviving siblings; pruned as the
    /// slot's last link detaches (see [`RetainedStaticTarget`]).
    retained_static: BTreeMap<u32, RetainedStaticTarget>,
    links: Vec<RegisteredLink>,
    /// Task 3 Stage A continuity witness: hook links, watched files and the
    /// refusal reason when instance routing is unavailable.
    instance: InstanceTracking,
    /// Background link cleanup, pre-started during preparation so the
    /// worker thread exists before any submit. `None` once a detach has
    /// driven it to completion; a fresh worker is created if links ever
    /// need closing afterwards.
    cleanup_worker: Option<CleanupWorker>,
}

/// A detach error leaves this Session's ownership bookkeeping inconsistent.
/// It does not prove a kernel producer survived or that the kernel is quiet;
/// recovery is a new Session. Refusing unrelated additions is the accepted
/// availability cost, while capture and cleanup of existing ownership continue.
pub(crate) fn attachment_admission(
    detach_failures: &[String],
    proposed_additions: bool,
) -> Result<()> {
    if proposed_additions && !detach_failures.is_empty() {
        bail!(
            "new producer attachment is refused after a detach bookkeeping failure; start a new session"
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AttachPreflight {
    pub(crate) lifecycle: bool,
    pub(crate) scope: bool,
}

fn attach_lifecycle_with<S, T>(
    state: &mut S,
    mut attach: impl FnMut(&mut S, &'static str) -> Result<T>,
    mut detach: impl FnMut(&mut S, &'static str, T) -> Result<()>,
) -> Result<Vec<T>> {
    let mut links = Vec::new();
    for program in ["sched_process_exec", "sched_process_exit", "task_newtask"] {
        match attach(state, program) {
            Ok(link) => links.push((program, link)),
            Err(error) => {
                let mut rollback_errors = Vec::new();
                for (attached_program, link) in links.into_iter().rev() {
                    if let Err(rollback) = detach(state, attached_program, link) {
                        rollback_errors
                            .push(format!("rolling back {attached_program}: {rollback:#}"));
                    }
                }
                let error = error.context(format!("attaching required {program}"));
                return if rollback_errors.is_empty() {
                    Err(error)
                } else {
                    Err(error.context(format!(
                        "lifecycle rollback failures: {}",
                        rollback_errors.join("; ")
                    )))
                };
            }
        }
    }
    Ok(links.into_iter().map(|(_, link)| link).collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProducerProgram {
    UProbe(&'static str),
    RawTracePoint(&'static str),
    BtfTracePoint(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ProbeSide {
    Return,
    Entry,
}

type StaticEndpoint = (u32, ProbeSide);

/// One link whose lifetime this session owns. Static, loader/export, and
/// lifecycle links all remain in this one registry.
enum RegisteredLink {
    UProbe {
        program: &'static str,
        slot: u32,
        id: UProbeLinkId,
    },
    /// One attached multi group side outside Aya's link table: the
    /// program, its member slots, and the live link fds (one per bisect
    /// leaf). Detach is drop: closing the fds detaches the links.
    MultiUProbe {
        program: &'static str,
        slots: Vec<u32>,
        fds: Vec<OwnedFd>,
    },
    RawTracePoint {
        program: &'static str,
        id: RawTracePointLinkId,
    },
    BtfTracePoint {
        program: &'static str,
        id: BtfTracePointLinkId,
    },
    DiagnosticUProbe {
        program: &'static str,
        id: UProbeLinkId,
    },
    DynamicUProbe {
        program: &'static str,
        context: LoaderContextId,
        object: PinnedObjectId,
        file_offset: u64,
        cookie: u64,
        abi: Option<HookAbi>,
        id: UProbeLinkId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DynamicExportIdentity {
    pub(crate) object: PinnedObjectId,
    pub(crate) file_offset: u64,
    pub(crate) cookie: u64,
    pub(crate) abi: HookAbi,
}

fn dynamic_export_snapshot_with<T>(
    links: &[T],
    context: LoaderContextId,
    mut identity: impl FnMut(&T) -> (LoaderContextId, Option<DynamicExportIdentity>),
) -> Vec<DynamicExportIdentity> {
    let mut snapshot = Vec::new();
    for link in links {
        let (linked_context, export) = identity(link);
        if linked_context != context {
            continue;
        }
        if let Some(export) = export
            && !snapshot.contains(&export)
        {
            snapshot.push(export);
        }
    }
    snapshot
}

impl RegisteredLink {
    fn producer(&self) -> ProducerProgram {
        match self {
            Self::UProbe { program, .. }
            | Self::MultiUProbe { program, .. }
            | Self::DynamicUProbe { program, .. }
            | Self::DiagnosticUProbe { program, .. } => ProducerProgram::UProbe(program),
            Self::RawTracePoint { program, .. } => ProducerProgram::RawTracePoint(program),
            Self::BtfTracePoint { program, .. } => ProducerProgram::BtfTracePoint(program),
        }
    }

    fn slots(&self) -> &[u32] {
        match self {
            Self::UProbe { slot, .. } => std::slice::from_ref(slot),
            Self::MultiUProbe { slots, .. } => slots,
            Self::RawTracePoint { .. }
            | Self::BtfTracePoint { .. }
            | Self::DiagnosticUProbe { .. }
            | Self::DynamicUProbe { .. } => &[],
        }
    }

    fn context(&self) -> Option<LoaderContextId> {
        match self {
            Self::DynamicUProbe { context, .. } => Some(*context),
            Self::UProbe { .. }
            | Self::MultiUProbe { .. }
            | Self::RawTracePoint { .. }
            | Self::BtfTracePoint { .. }
            | Self::DiagnosticUProbe { .. } => None,
        }
    }
}

fn links_cover_slot(links: &[RegisteredLink], slot: u32) -> bool {
    links.iter().any(|link| link.slots().contains(&slot))
}

/// The smallest requested slot that shares a multi group link with a
/// slot outside the request, if any. Group links are immutable: a
/// bundle drops only when every member is requested, so a partially
/// covered member triggers the explicit group rebuild while fully
/// covered bundles still detach outright.
fn find_partial_multi_member(links: &[RegisteredLink], slots: &BTreeSet<u32>) -> Option<u32> {
    slots.iter().copied().find(|slot| {
        links.iter().any(|link| {
            matches!(link, RegisteredLink::MultiUProbe { slots: members, .. }
                if members.contains(slot)
                    && members.iter().any(|member| !slots.contains(member)))
        })
    })
}

/// Every slot sharing a multi group link with `requested`, transitively:
/// partially covered bundles pull in their survivors, and bundles
/// overlapping those survivors join too (a return bundle widened by an
/// entry-refused member shares its sibling's entry bundle). Returns `None`
/// when no multi bundle is partially covered, i.e. the plain detach path
/// applies: whole bundles, singles, and unlinked slots.
fn plan_group_rebuild(
    links: &[RegisteredLink],
    requested: &BTreeSet<u32>,
) -> Option<BTreeSet<u32>> {
    find_partial_multi_member(links, requested)?;
    let mut affected: BTreeSet<u32> = requested.clone();
    loop {
        let mut grown = false;
        for link in links {
            let RegisteredLink::MultiUProbe { slots: members, .. } = link else {
                continue;
            };
            if members.iter().any(|member| affected.contains(member))
                && members.iter().any(|member| !affected.contains(member))
            {
                affected.extend(members.iter().copied());
                grown = true;
            }
        }
        if !grown {
            break;
        }
    }
    Some(affected)
}

/// How many live multi groups one rebuild disturbs: bundles sharing a
/// member are sides of one group (a return bundle widened by refusals
/// still shares its sibling's entry bundle), disjoint bundles are
/// distinct groups. Each disturbed group is one published gap window.
fn affected_group_count(links: &[RegisteredLink], affected: &BTreeSet<u32>) -> u64 {
    let mut components: Vec<BTreeSet<u32>> = Vec::new();
    for link in links {
        let RegisteredLink::MultiUProbe { slots: members, .. } = link else {
            continue;
        };
        if !members.iter().any(|member| affected.contains(member)) {
            continue;
        }
        let mut merged: BTreeSet<u32> = members.iter().copied().collect();
        components.retain(|component| {
            if component.intersection(&merged).next().is_none() {
                true
            } else {
                merged.extend(component.iter().copied());
                false
            }
        });
        components.push(merged);
    }
    components.len() as u64
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct CounterSnapshot {
    pub(crate) ring_loss: u64,
    pub(crate) export_state_failures: u64,
    pub(crate) export_bounded_read_failures: u64,
    pub(crate) loader_hits: u64,
    pub(crate) loader_state_read_failures: u64,
    pub(crate) abi_refusals: u64,
}

impl CounterSnapshot {
    pub(crate) fn replace_with(&mut self, next: Self) -> bool {
        let nondecreasing = next.ring_loss >= self.ring_loss
            && next.export_state_failures >= self.export_state_failures
            && next.export_bounded_read_failures >= self.export_bounded_read_failures
            && next.loader_hits >= self.loader_hits
            && next.loader_state_read_failures >= self.loader_state_read_failures
            && next.abi_refusals >= self.abi_refusals;
        if nondecreasing {
            *self = next;
        }
        nondecreasing
    }
}

fn counter_snapshot_with(
    mut read: impl FnMut(u32) -> Result<u64>,
    abi_refusals: u64,
) -> Result<CounterSnapshot> {
    Ok(CounterSnapshot {
        ring_loss: read(DISCOVERY_COUNTER_RING_LOSS)?,
        export_state_failures: read(DISCOVERY_COUNTER_EXPORT_STATE_FAILURES)?,
        export_bounded_read_failures: read(DISCOVERY_COUNTER_EXPORT_BOUNDED_READ_FAILURES)?,
        loader_hits: read(DISCOVERY_COUNTER_LOADER_HITS)?,
        loader_state_read_failures: read(DISCOVERY_COUNTER_LOADER_STATE_READ_FAILURES)?,
        abi_refusals,
    })
}

/// Detaches each concrete registered link in producer order. A program can
/// own many links (one per static or dynamic slot), so ordering the producers
/// is not enough: every individual link must receive one best-effort attempt.
fn detach_selected_with<T>(
    mut selected: Vec<(ProducerProgram, T)>,
    mut detach: impl FnMut(T) -> Result<()>,
) -> Vec<anyhow::Error> {
    selected.sort_by_key(|(producer, _)| match producer {
        ProducerProgram::UProbe("p11_entry") => 0,
        ProducerProgram::UProbe("p11_entry_ia32") => 1,
        ProducerProgram::UProbe("p11_entry_template") => 2,
        ProducerProgram::UProbe("p11_entry_template_types") => 3,
        ProducerProgram::UProbe("p11_entry_template_pair") => 4,
        ProducerProgram::BtfTracePoint("task_newtask") => 5,
        ProducerProgram::UProbe("p11_return") => 6,
        ProducerProgram::RawTracePoint(_) => 8,
        _ => 7,
    });
    selected
        .into_iter()
        .filter_map(|(_, link)| detach(link).err())
        .collect()
}

#[derive(Default)]
struct DynamicAttachEvidence(bool);

impl DynamicAttachEvidence {
    fn record<T, E>(&mut self, result: std::result::Result<T, E>) -> std::result::Result<T, E> {
        if result.is_ok() {
            self.0 = true;
        }
        result
    }

    fn successful(&self) -> bool {
        self.0
    }
}

fn record_dynamic_attach_with<S, T, E>(
    state: &mut S,
    evidence: &mut DynamicAttachEvidence,
    attach: impl FnOnce(&mut S) -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    evidence.record(attach(state))
}

fn attach_dynamic_export_with<S, T, E>(
    state: &mut S,
    evidence: &mut DynamicAttachEvidence,
    mut attach: impl FnMut(&mut S, bool) -> std::result::Result<T, E>,
    mut detach_return: impl FnMut(&mut S, T),
) -> std::result::Result<(T, T), E> {
    let return_id = record_dynamic_attach_with(state, evidence, |state| attach(state, true))?;
    match record_dynamic_attach_with(state, evidence, |state| attach(state, false)) {
        Ok(entry_id) => Ok((entry_id, return_id)),
        Err(error) => {
            detach_return(state, return_id);
            Err(error)
        }
    }
}

/// Renders `e` and every `.source()` beneath it, joined by `: `. Several
/// of aya's error variants (e.g. `ProgramError::SyscallError`) are
/// `#[error(transparent)]`, so `{e}` alone prints only the outer
/// message (`` `perf_event_open` failed ``) and silently drops the
/// actual OS error (`EPERM`/`EACCES`/...) that explains *why* — that
/// detail lives one level down in `.source()`. `anyhow`'s `{:#}` does
/// this same walk for an `anyhow::Error`; this is the equivalent for a
/// plain `std::error::Error` this code does not otherwise wrap, so the
/// per-slot attach failure text below is not silently missing the one
/// fact an operator needs (was it a permission error, and which one).
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut msg = e.to_string();
    let mut cur = e.source();
    while let Some(src) = cur {
        msg.push_str(": ");
        msg.push_str(&src.to_string());
        cur = src.source();
    }
    msg
}

fn entry_program(
    semantics: &SlotSemantics,
    policy: CapturePolicy,
    object_has_unsafe: bool,
    target_abi: ElfAbi,
) -> &'static str {
    if policy.uses_unsafe_decoders() && semantics.template1_arg != ARG_NONE {
        "p11_entry_template_pair"
    } else if policy.uses_unsafe_decoders()
        && semantics.semantic_flags & p11scope_ebpf_common::semantic_flags::TEMPLATE0_TYPES_ONLY
            != 0
    {
        "p11_entry_template_types"
    } else if policy.uses_unsafe_decoders() && semantics.template0_arg != ARG_NONE {
        "p11_entry_template"
    } else if object_has_unsafe && target_abi == ElfAbi::Ilp32 {
        "p11_entry_ia32"
    } else {
        "p11_entry"
    }
}

#[derive(Debug)]
struct AttachOutcome {
    successful: BTreeSet<StaticEndpoint>,
    failures: Vec<(u32, String)>,
    completed: Vec<SlotCompletion>,
    /// The run stopped early on fd exhaustion: members without a success
    /// or failure entry were never attempted. Fresh attach reports the one
    /// shared summary; the group rebuild records every remainder explicitly.
    exhausted: bool,
}

type SlotCompletion = (u32, Option<u64>);
type TargetAttachResult = (Vec<u32>, Vec<SlotCompletion>);

/// What one [`Session::replace_targets`] call attached: the replacements
/// that completed, whether their cleanup detach failed, and any group
/// rebuilds that cleanup triggered.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplacementOutcome {
    /// (slot, attach timestamp) for every replacement fully attached.
    pub completed: Vec<(u32, Option<u64>)>,
    /// A partial replacement detach failed once; the caller blocks additions.
    pub failed_detach: bool,
    /// Group rebuilds the replacement's cleanup detaches triggered.
    pub rebuild: DetachOutcome,
}

/// What one [`Session::detach_slots`] call rebuilt, if anything: per-member
/// evidence for multi-group survivors plus the gap count. Empty when no
/// group needed a rebuild (singles detach, whole-bundle detach).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DetachOutcome {
    /// (slot, reactivation timestamp) for every survivor fully reattached,
    /// including unchanged siblings.
    pub recompleted: Vec<(u32, Option<u64>)>,
    /// (slot, reason) for every survivor that lost its links; the caller
    /// deactivates these in the plan exactly like failed fresh targets.
    pub rebuild_failures: Vec<(u32, String)>,
    /// How many groups dropped and rebuilt: one published gap window each.
    pub rebuilt_groups: u64,
}

fn export_programs(abi: HookAbi) -> (&'static str, &'static str) {
    match abi {
        HookAbi::FunctionList => ("function_list_entry", "function_list_return"),
        HookAbi::InterfaceList => ("interface_list_entry", "interface_list_return"),
        HookAbi::Interface => ("interface_entry", "interface_return"),
    }
}

fn static_probe_side(program: &str) -> Option<ProbeSide> {
    match program {
        "p11_return" => Some(ProbeSide::Return),
        "p11_entry"
        | "p11_entry_ia32"
        | "p11_entry_template"
        | "p11_entry_template_types"
        | "p11_entry_template_pair" => Some(ProbeSide::Entry),
        _ => None,
    }
}

fn static_endpoint(program: &str, slot: u32) -> Option<StaticEndpoint> {
    static_probe_side(program).map(|side| (slot, side))
}

/// One member of a static attach group: the slot plus its resolved
/// multi-link site (file offset + attach cookie).
#[derive(Debug, Clone)]
struct StaticGroupMember {
    slot: Slot,
    offset: u64,
    cookie: u64,
}

/// One multi-attach unit: all slots sharing an attach path AND an entry
/// program take one return link plus one entry link. Members are sorted
/// by slot so link order is deterministic.
#[derive(Debug)]
struct StaticGroup {
    path: PathBuf,
    entry_program: &'static str,
    members: Vec<StaticGroupMember>,
}

/// One statically attached slot's exact reattach facts: the descriptor the
/// attach used plus the pinned path/ABI it resolved. Retained so a
/// multi-group rebuild can reattach surviving siblings without re-deriving
/// identity; facts survive exactly while a link does.
#[derive(Debug, Clone)]
struct RetainedStaticTarget {
    slot: Slot,
    path: PathBuf,
    abi: ElfAbi,
}

/// Session-owned attachment authority. Fields and constructor stay private.
pub(crate) struct AttachedSemanticSet {
    domain: crate::attach::capture::NativeDomainId,
    subset: crate::inventory_semantics::AttestedSubset,
}

impl std::fmt::Debug for AttachedSemanticSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AttachedSemanticSet(<retained>)")
    }
}

fn seal_attached_subset_with(
    subset: crate::inventory_semantics::AttestedSubset,
    domain: crate::attach::capture::NativeDomainId,
    policy: CapturePolicy,
    descriptors: Result<Vec<SlotSemantics>>,
    retained: &BTreeMap<u32, RetainedStaticTarget>,
    owned_sides: &BTreeSet<StaticEndpoint>,
    watched: impl Fn(PinnedObjectId) -> Option<crate::discovery::identity::RetainedInventoryTarget>,
) -> std::result::Result<AttachedSemanticSet, crate::inventory_semantics::SemanticRefusal> {
    let attached = AttachedSemanticSet { domain, subset };
    attached.validate_with(domain, policy, descriptors, retained, owned_sides, watched)?;
    Ok(attached)
}

impl AttachedSemanticSet {
    fn validate_with(
        &self,
        domain: crate::attach::capture::NativeDomainId,
        policy: CapturePolicy,
        descriptors: Result<Vec<SlotSemantics>>,
        retained: &BTreeMap<u32, RetainedStaticTarget>,
        owned_sides: &BTreeSet<StaticEndpoint>,
        watched: impl Fn(PinnedObjectId) -> Option<crate::discovery::identity::RetainedInventoryTarget>,
    ) -> std::result::Result<(), crate::inventory_semantics::SemanticRefusal> {
        use crate::inventory_semantics::SemanticRefusal;
        if domain != self.domain || policy != CapturePolicy::Allowlisted {
            return Err(SemanticRefusal::Attachment);
        }
        if descriptors.map_err(|_| SemanticRefusal::Descriptor)? != *crate::kinds::DESCRIPTORS {
            return Err(SemanticRefusal::Descriptor);
        }
        let plan = self.subset.plan();
        let pins = self.subset.pins();
        if plan.validate_slot_index().is_err() || self.subset.required().is_empty() {
            return Err(SemanticRefusal::IncompleteProvider);
        }
        if pins.check_unchanged() != Ok(true) {
            return Err(SemanticRefusal::ProviderInstanceUnproven);
        }
        let mut checked = BTreeSet::new();
        for (provider, required) in self.subset.required() {
            if required.is_empty() {
                return Err(SemanticRefusal::IncompleteProvider);
            }
            for index in required {
                let slot = plan
                    .slots
                    .get(*index as usize)
                    .ok_or(SemanticRefusal::Attachment)?;
                let actual = retained.get(index).ok_or(SemanticRefusal::Attachment)?;
                if actual.slot != *slot
                    || !owned_sides.contains(&(*index, ProbeSide::Entry))
                    || !owned_sides.contains(&(*index, ProbeSide::Return))
                    || Some(actual.abi) != pins.abi_for(slot.object)
                    || Some(&actual.path) != pins.attach_path_for(slot.object).as_ref().ok()
                {
                    return Err(SemanticRefusal::Attachment);
                }
                // One watched dependency image cannot establish the provider's
                // load instance. Equal digests/local IDs never replace held custody.
                let target =
                    watched(slot.object).ok_or(SemanticRefusal::ProviderInstanceUnproven)?;
                if slot.object != *provider
                    || !target.same_object_as(pins, *provider)
                    || target.check_unchanged() != Ok(true)
                {
                    return Err(SemanticRefusal::ProviderInstanceUnproven);
                }
                checked.insert(*index);
            }
        }
        if checked.len() != plan.slots.len() {
            return Err(SemanticRefusal::IncompleteProvider);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "inventory_semantics_tests.rs"]
mod inventory_semantics_tests;

/// Retains exact reattach facts for every requested slot that gained a
/// link. Reattach overwrites: a replacement's new descriptor supersedes
/// the frozen one the rebuild pruned.
fn retain_from_successful(
    retained: &mut BTreeMap<u32, RetainedStaticTarget>,
    targets: &[Slot],
    attach_targets: &BTreeMap<u32, (PathBuf, ElfAbi)>,
    successful: &BTreeSet<StaticEndpoint>,
) {
    let linked: BTreeSet<u32> = successful.iter().map(|(slot, _)| *slot).collect();
    for slot in targets {
        if !linked.contains(&slot.index) {
            continue;
        }
        let (path, abi) = attach_targets
            .get(&slot.index)
            .expect("every selected target has retained pinned facts");
        retained.insert(
            slot.index,
            RetainedStaticTarget {
                slot: slot.clone(),
                path: path.clone(),
                abi: *abi,
            },
        );
    }
}

/// Drops retained facts for slots with no remaining link. The rebuild
/// consults facts only for link-carrying survivors, so pruning is what
/// keeps a detached slot's descriptor from ever reattaching stale.
fn prune_linkless_retained(
    retained: &mut BTreeMap<u32, RetainedStaticTarget>,
    links: &[RegisteredLink],
) {
    retained.retain(|slot, _| links_cover_slot(links, *slot));
}

fn group_static_slots(
    slots: &[Slot],
    policy: CapturePolicy,
    object_has_unsafe: bool,
    attach_targets: &BTreeMap<u32, (PathBuf, ElfAbi)>,
) -> Vec<StaticGroup> {
    let mut by_key: BTreeMap<(PathBuf, &'static str), Vec<StaticGroupMember>> = BTreeMap::new();
    for slot in slots {
        let (path, abi) = attach_targets
            .get(&slot.index)
            .expect("every selected target has retained pinned facts");
        let UProbeAttachPoint {
            location: UProbeAttachLocation::AbsoluteOffset(offset),
            cookie: Some(cookie),
        } = slot_attach_point(slot)
        else {
            unreachable!("static attach points are absolute with cookies");
        };
        let program = entry_program(&slot.semantics, policy, object_has_unsafe, *abi);
        by_key
            .entry((path.clone(), program))
            .or_default()
            .push(StaticGroupMember {
                slot: slot.clone(),
                offset,
                cookie,
            });
    }
    by_key
        .into_iter()
        .map(|((path, entry_program), mut members)| {
            members.sort_by_key(|member| member.slot.index);
            StaticGroup {
                path,
                entry_program,
                members,
            }
        })
        .collect()
}

/// One attached group side: the program, its member slots, and the live
/// links (one per bisect leaf). Generic over the link handle so the
/// orchestration unit-tests without fds; production uses `OwnedFd`.
#[derive(Debug)]
struct MultiLinkBundle<T> {
    program: &'static str,
    slots: Vec<u32>,
    links: Vec<T>,
}

/// Explicit failure for a slot left without a completed pair when fd exhaustion
/// stops attachment. Callers detach and deactivate exactly the failed indices,
/// so an unlisted slot would stay link-less or keep an entry-less return link.
fn unfinished_after_exhaustion(slot: u32) -> (u32, String) {
    (
        slot,
        format!(
            "fd table exhausted before slot {slot} was fully attached; \
             raise RLIMIT_NOFILE (ulimit -n) and retry"
        ),
    )
}

fn exhausted_multi(slot: u32, endpoints: usize, links: usize) -> (u32, String) {
    (
        slot,
        format!(
            "fd table exhausted attaching slot {slot} ({endpoints} endpoints across {links} links); \
             raise RLIMIT_NOFILE (ulimit -n) and retry"
        ),
    )
}

/// Attaches regrouped static slots: per group, the return link(s) first,
/// then the entry link(s) over the return-paired members only, so an
/// entry is never attempted without its return. Kernel-rejected offsets
/// bisect into per-slot failures; permission errors fail the side and
/// the loop continues with the next group; fd exhaustion ends the run
/// with one summary like singles; an unsupported kernel aborts with
/// [`BackendFallbackRequired`]. Returns the live links (one bundle per
/// attached side) plus the singles-shaped [`AttachOutcome`].
fn attach_target_groups_with<T>(
    groups: &[StaticGroup],
    completed_at: impl FnMut(&Slot) -> Option<u64>,
    attach_link: impl FnMut(&'static str, &Path, &[(u64, u64)], bool) -> io::Result<T>,
) -> Result<(Vec<MultiLinkBundle<T>>, AttachOutcome), BackendFallbackRequired> {
    let (bundles, mut outcome) = attach_target_groups_unsettled(groups, completed_at, attach_link)?;
    if outcome.exhausted {
        // As for singles: after the summary, every member without a completed
        // pair fails explicitly. Groups attach whole, so each kept bundle then
        // belongs entirely to completed or entirely to failed members.
        let mut settled: BTreeSet<u32> = outcome.failures.iter().map(|(slot, _)| *slot).collect();
        settled.extend(outcome.completed.iter().map(|(slot, _)| *slot));
        for member in groups.iter().flat_map(|group| &group.members) {
            if settled.insert(member.slot.index) {
                outcome
                    .failures
                    .push(unfinished_after_exhaustion(member.slot.index));
            }
        }
    }
    Ok((bundles, outcome))
}

/// [`attach_target_groups_with`] without settling unfinished members after
/// exhaustion: the rebuild path records its own `was not reattached` remainder.
fn attach_target_groups_unsettled<T>(
    groups: &[StaticGroup],
    mut completed_at: impl FnMut(&Slot) -> Option<u64>,
    mut attach_link: impl FnMut(&'static str, &Path, &[(u64, u64)], bool) -> io::Result<T>,
) -> Result<(Vec<MultiLinkBundle<T>>, AttachOutcome), BackendFallbackRequired> {
    let mut successful = BTreeSet::new();
    let mut failures = Vec::new();
    let mut completed = Vec::new();
    let mut bundles = Vec::new();
    let mut links_attached = 0usize;
    for group in groups {
        let sites: Vec<(u64, u64)> = group
            .members
            .iter()
            .map(|member| (member.offset, member.cookie))
            .collect();
        let (return_links, return_refused) = match bisect_attach(
            &mut |slice| attach_link("p11_return", &group.path, slice, true),
            &sites,
        ) {
            Ok(ok) => ok,
            Err(GroupHalt::Unsupported(error)) => {
                return Err(BackendFallbackRequired::unsupported(error));
            }
            Err(GroupHalt::Exhausted(_)) => {
                let first = group.members.first().expect("groups are never empty");
                failures.push(exhausted_multi(
                    first.slot.index,
                    successful.len(),
                    links_attached,
                ));
                return Ok((
                    bundles,
                    AttachOutcome {
                        successful,
                        failures,
                        completed,
                        exhausted: true,
                    },
                ));
            }
        };
        links_attached += return_links.len();
        let refused: BTreeSet<usize> = return_refused.iter().map(|site| site.index).collect();
        for site in &return_refused {
            let member = &group.members[site.index];
            failures.push((
                member.slot.index,
                format!(
                    "p11_return at {}+{:#x}: {}",
                    group.path.display(),
                    member.offset,
                    error_chain(&site.error)
                ),
            ));
        }
        let paired: Vec<&StaticGroupMember> = group
            .members
            .iter()
            .enumerate()
            .filter(|(index, _)| !refused.contains(index))
            .map(|(_, member)| member)
            .collect();
        for member in &paired {
            successful.insert(
                static_endpoint("p11_return", member.slot.index)
                    .expect("p11_return is a static endpoint"),
            );
        }
        if !return_links.is_empty() {
            bundles.push(MultiLinkBundle {
                program: "p11_return",
                slots: paired.iter().map(|member| member.slot.index).collect(),
                links: return_links,
            });
        }
        if paired.is_empty() {
            continue;
        }
        let entry_sites: Vec<(u64, u64)> = paired
            .iter()
            .map(|member| (member.offset, member.cookie))
            .collect();
        let (entry_links, entry_refused) = match bisect_attach(
            &mut |slice| attach_link(group.entry_program, &group.path, slice, false),
            &entry_sites,
        ) {
            Ok(ok) => ok,
            Err(GroupHalt::Unsupported(error)) => {
                return Err(BackendFallbackRequired::unsupported(error));
            }
            Err(GroupHalt::Exhausted(_)) => {
                failures.push(exhausted_multi(
                    paired[0].slot.index,
                    successful.len(),
                    links_attached,
                ));
                return Ok((
                    bundles,
                    AttachOutcome {
                        successful,
                        failures,
                        completed,
                        exhausted: true,
                    },
                ));
            }
        };
        links_attached += entry_links.len();
        let refused: BTreeSet<usize> = entry_refused.iter().map(|site| site.index).collect();
        for site in &entry_refused {
            let member = paired[site.index];
            failures.push((
                member.slot.index,
                format!(
                    "{} at {}+{:#x}: {}",
                    group.entry_program,
                    group.path.display(),
                    member.offset,
                    error_chain(&site.error)
                ),
            ));
        }
        let mut entry_slots = Vec::new();
        for (index, member) in paired.iter().enumerate() {
            if refused.contains(&index) {
                continue;
            }
            successful.insert(
                static_endpoint(group.entry_program, member.slot.index)
                    .expect("selected entry program is a static endpoint"),
            );
            completed.push((member.slot.index, completed_at(&member.slot)));
            entry_slots.push(member.slot.index);
        }
        if !entry_links.is_empty() {
            bundles.push(MultiLinkBundle {
                program: group.entry_program,
                slots: entry_slots,
                links: entry_links,
            });
        }
    }
    Ok((
        bundles,
        AttachOutcome {
            successful,
            failures,
            completed,
            exhausted: false,
        },
    ))
}

/// Records every survivor a halted rebuild never attempted. A silent
/// link-less survivor would violate the rebuild's exact-evidence rule,
/// so each one carries the halt reason explicitly.
fn fail_unreattached(
    failures: &mut Vec<(u32, String)>,
    slots: impl IntoIterator<Item = u32>,
    reason: &str,
) {
    for slot in slots {
        failures.push((slot, format!("slot {slot} was not reattached: {reason}")));
    }
}

/// Drops one dirty round's bundles entries-first, mirroring the detach
/// order [`detach_selected_with`] applies to live links: no return outlives
/// the entry it pairs with.
fn detach_rebuild_round<T>(
    detach_bundles: &mut impl FnMut(Vec<MultiLinkBundle<T>>),
    mut bundles: Vec<MultiLinkBundle<T>>,
) {
    bundles.sort_by_key(|bundle| match static_probe_side(bundle.program) {
        Some(ProbeSide::Entry) => 0,
        Some(ProbeSide::Return) => 1,
        None => 2,
    });
    detach_bundles(bundles);
}

/// Reattaches regrouped rebuild survivors to fixpoint, one group at a
/// time: returns before entries per group (via
/// [`attach_target_groups_with`]), so an entry-partial survivor (return
/// live, entry refused) drops with its exact failure and the round's
/// bundles detach entries-first before the remainder reattaches. A clean
/// group's bundles are never detached for another group's partial. Only
/// kept links contribute successes or completions; fd exhaustion and an
/// unsupported kernel stop the run with every remainder recorded
/// explicitly. Terminates: every dirty round strictly shrinks its group.
fn reattach_rebuilt_groups_with<T>(
    groups: &[StaticGroup],
    mut completed_at: impl FnMut(&Slot) -> Option<u64>,
    mut attach_link: impl FnMut(&'static str, &Path, &[(u64, u64)], bool) -> io::Result<T>,
    mut detach_bundles: impl FnMut(Vec<MultiLinkBundle<T>>),
) -> (Vec<MultiLinkBundle<T>>, AttachOutcome) {
    let mut kept = Vec::new();
    let mut successful = BTreeSet::new();
    let mut failures = Vec::new();
    let mut completed = Vec::new();
    let mut exhausted = false;
    for (position, group) in groups.iter().enumerate() {
        let later = || {
            groups[position + 1..]
                .iter()
                .flat_map(|later| later.members.iter().map(|member| member.slot.index))
        };
        let mut remaining: Vec<StaticGroupMember> = group.members.clone();
        while !remaining.is_empty() {
            let round = StaticGroup {
                path: group.path.clone(),
                entry_program: group.entry_program,
                members: std::mem::take(&mut remaining),
            };
            let (bundles, outcome) = match attach_target_groups_unsettled(
                std::slice::from_ref(&round),
                &mut completed_at,
                &mut attach_link,
            ) {
                Ok(ok) => ok,
                Err(sentinel) => {
                    fail_unreattached(
                        &mut failures,
                        round
                            .members
                            .iter()
                            .map(|member| member.slot.index)
                            .chain(later()),
                        &format!("{sentinel:#}"),
                    );
                    return (
                        kept,
                        AttachOutcome {
                            successful,
                            failures,
                            completed,
                            exhausted,
                        },
                    );
                }
            };
            if outcome.exhausted {
                // The fd table is full: nothing more can attach. The round's
                // bundles drop — a kept return without its entry would strand
                // a partial link — and every member without an entry is
                // recorded explicitly instead of staying silently link-less.
                exhausted = true;
                let failed: BTreeSet<u32> =
                    outcome.failures.iter().map(|(slot, _)| *slot).collect();
                failures.extend(outcome.failures);
                detach_rebuild_round(&mut detach_bundles, bundles);
                fail_unreattached(
                    &mut failures,
                    round
                        .members
                        .iter()
                        .map(|member| member.slot.index)
                        .filter(|slot| !failed.contains(slot))
                        .chain(later()),
                    "fd table exhausted; raise RLIMIT_NOFILE (ulimit -n) and retry",
                );
                return (
                    kept,
                    AttachOutcome {
                        successful,
                        failures,
                        completed,
                        exhausted,
                    },
                );
            }
            let partials: BTreeSet<u32> = round
                .members
                .iter()
                .map(|member| member.slot.index)
                .filter(|slot| {
                    outcome.successful.contains(&(*slot, ProbeSide::Return))
                        && !outcome.successful.contains(&(*slot, ProbeSide::Entry))
                })
                .collect();
            // A member refused this round (its return, or its entry beside
            // a partial) already carries its failure: it is not re-rounded,
            // so the refusal is recorded once (F-45).
            let refused: BTreeSet<u32> = outcome.failures.iter().map(|(slot, _)| *slot).collect();
            failures.extend(outcome.failures);
            if partials.is_empty() {
                successful.extend(outcome.successful);
                completed.extend(outcome.completed);
                kept.extend(bundles);
            } else {
                // The round's links all drop, so none of its successes or
                // completions describe a kept link; the remainder re-rounds
                // and re-completes with its final reactivation time.
                detach_rebuild_round(&mut detach_bundles, bundles);
                remaining = round
                    .members
                    .into_iter()
                    .filter(|member| {
                        !partials.contains(&member.slot.index)
                            && !refused.contains(&member.slot.index)
                    })
                    .collect();
            }
        }
    }
    (
        kept,
        AttachOutcome {
            successful,
            failures,
            completed,
            exhausted,
        },
    )
}

/// Raw fd of a loaded static twin for the multi `link_create` leaf:
/// resolved once per program before the first group link so a missing
/// program fails fast instead of bisecting into per-slot refusals. The
/// fd stays owned by `ebpf` for the whole attach.
fn multi_prog_fd(ebpf: &mut Ebpf, program: &'static str) -> Result<RawFd> {
    let probe: &mut UProbe = ebpf
        .program_mut(program)
        .with_context(|| format!("program {program} missing from object"))?
        .try_into()?;
    let fd = probe
        .fd()
        .with_context(|| format!("program {program} has no loaded fd"))?;
    Ok(fd.as_fd().as_raw_fd())
}

/// PID filter for a uprobe-multi `link_create` (DR-CLASSIC-PID0): the
/// target under PID scope, which [`select_session_backend`] allows only
/// where the functional probe proved the kernel filter covers every thread
/// of the named process and excludes every other process (and so a later
/// process reusing the PID); 0 (all processes) under cgroup and system
/// scope, which the in-BPF scope gate enforces. The in-BPF PID_FILTER tgid
/// guard every static probe consults via `scope_auth` stays under PID
/// scope as defence in depth.
pub(crate) fn multi_link_pid(scope: UProbeScope) -> u32 {
    match scope {
        UProbeScope::OneProcess(pid) => pid.get(),
        // Never widen to pid 0 for a scope that names one process.
        UProbeScope::CallingProcess => std::process::id(),
        UProbeScope::AllProcesses => 0,
    }
}

pub(crate) fn monotonic_ns() -> Option<u64> {
    let mut timestamp = std::mem::MaybeUninit::<libc::timespec>::uninit();
    // SAFETY: `clock_gettime` initializes `timestamp` on success.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, timestamp.as_mut_ptr()) } != 0 {
        return None;
    }
    // SAFETY: the successful call above initialized `timestamp`.
    let timestamp = unsafe { timestamp.assume_init() };
    let seconds = u64::try_from(timestamp.tv_sec).ok()?;
    let nanos = u64::try_from(timestamp.tv_nsec).ok()?;
    seconds.checked_mul(1_000_000_000)?.checked_add(nanos)
}

/// Keeps the static return-then-entry ordering intact while making the one
/// per-slot dependency explicit: no entry link exists unless its return link
/// was created first. The closures are the existing Aya lifecycle seam and
/// make the failure policy testable without a privileged attachment.
fn slot_attach_point(slot: &Slot) -> UProbeAttachPoint<'static> {
    UProbeAttachPoint {
        location: UProbeAttachLocation::AbsoluteOffset(slot.file_offset),
        cookie: Some(attach_cookie(slot.index, slot.descriptor_index)),
    }
}

/// True when the attach error chain bottoms out at EMFILE: the fd table is
/// full, so every further link would fail identically.
pub(crate) fn is_fd_exhaustion(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<io::Error>(),
            Some(io) if io.raw_os_error() == Some(libc::EMFILE)
        )
    })
}

fn static_attach_error(
    program: &str,
    slot: &Slot,
    error: aya::programs::ProgramError,
) -> anyhow::Error {
    anyhow::Error::new(error).context(format!(
        "{program} at {}+{:#x}",
        slot.object_path, slot.file_offset
    ))
}

fn attach_targets_with(
    slots: &[Slot],
    policy: CapturePolicy,
    object_has_unsafe: bool,
    mut abi_for: impl FnMut(&Slot) -> Result<ElfAbi>,
    mut attach: impl FnMut(&'static str, &Slot, UProbeAttachPoint<'static>) -> Result<()>,
    mut completed_at: impl FnMut(&Slot) -> Option<u64>,
) -> Result<AttachOutcome> {
    // Resolve every retained target ABI before the first return attachment.
    // This keeps each return/entry pair bound to the same pinned object fact.
    let targets = slots
        .iter()
        .map(|slot| abi_for(slot).map(|abi| (slot, abi)))
        .collect::<Result<Vec<_>>>()?;
    let mut successful = BTreeSet::new();
    let mut failures = Vec::new();
    let mut completed = Vec::new();
    let mut return_attached = BTreeSet::new();
    // EMFILE ends the run with one summary: links are retained, so no later
    // slot could succeed once the table is full.
    let exhausted =
        |slot: &Slot, successful: &BTreeSet<(u32, ProbeSide)>, error: &anyhow::Error| {
            (
                slot.index,
                format!(
                    "fd table exhausted attaching slot {} ({} links attached); \
                 raise RLIMIT_NOFILE (ulimit -n) and retry: {error:#}",
                    slot.index,
                    successful.len()
                ),
            )
        };
    // After the summary, fail every slot without a completed pair explicitly:
    // callers detach and deactivate exactly the failed indices, so an
    // unlisted slot would stay link-less or keep a return that can never pair.
    let fail_unfinished = |failures: &mut Vec<(u32, String)>, completed: &[(u32, Option<u64>)]| {
        let mut settled: BTreeSet<u32> = failures.iter().map(|(slot, _)| *slot).collect();
        settled.extend(completed.iter().map(|(slot, _)| *slot));
        for (slot, _) in &targets {
            if settled.insert(slot.index) {
                failures.push(unfinished_after_exhaustion(slot.index));
            }
        }
    };
    for (slot, _) in &targets {
        match attach("p11_return", slot, slot_attach_point(slot)) {
            Ok(()) => {
                successful.insert(
                    static_endpoint("p11_return", slot.index)
                        .expect("p11_return is a static endpoint"),
                );
                return_attached.insert(slot.index);
            }
            Err(error) => {
                if is_fd_exhaustion(&error) {
                    failures.push(exhausted(slot, &successful, &error));
                    fail_unfinished(&mut failures, &completed);
                    return Ok(AttachOutcome {
                        successful,
                        failures,
                        completed,
                        exhausted: true,
                    });
                }
                failures.push((slot.index, format!("{error:#}")));
            }
        }
    }

    let entry_programs: &[&str] = if object_has_unsafe {
        &[
            "p11_entry",
            "p11_entry_ia32",
            "p11_entry_template",
            "p11_entry_template_types",
            "p11_entry_template_pair",
        ]
    } else {
        &["p11_entry"]
    };
    for program in entry_programs {
        for (slot, abi) in &targets {
            if !return_attached.contains(&slot.index)
                || entry_program(&slot.semantics, policy, object_has_unsafe, *abi) != *program
            {
                continue;
            }
            match attach(program, slot, slot_attach_point(slot)) {
                Ok(()) => {
                    successful.insert(
                        static_endpoint(program, slot.index)
                            .expect("selected entry program is a static endpoint"),
                    );
                    completed.push((slot.index, completed_at(slot)));
                }
                Err(error) => {
                    if is_fd_exhaustion(&error) {
                        failures.push(exhausted(slot, &successful, &error));
                        fail_unfinished(&mut failures, &completed);
                        return Ok(AttachOutcome {
                            successful,
                            failures,
                            completed,
                            exhausted: true,
                        });
                    }
                    failures.push((slot.index, format!("{error:#}")));
                }
            }
        }
    }
    Ok(AttachOutcome {
        successful,
        failures,
        completed,
        exhausted: false,
    })
}

fn standard_async_catalog() -> Result<BTreeMap<FunctionNameKey, u32>> {
    let fields = pkcs11_module::FUNCTION_LIST_FIELDS
        .iter()
        .chain(pkcs11_module::FUNCTION_LIST_3_0_EXTRA_FIELDS)
        .chain(pkcs11_module::FUNCTION_LIST_3_2_EXTRA_FIELDS);
    let mut catalog = BTreeMap::new();
    for (id, field) in fields.enumerate() {
        if field.name.len() > FUNCTION_NAME_MAX_BYTES {
            bail!("standard function name is too long: {}", field.name);
        }
        let mut snapshot = [0u8; FUNCTION_NAME_MAX_BYTES + 1];
        snapshot[..field.name.len()].copy_from_slice(field.name.as_bytes());
        let key = FunctionNameKey::from_bytes(&snapshot[..=field.name.len()])
            .with_context(|| format!("invalid standard function name {}", field.name))?;
        if let Some(previous) = catalog.insert(key, id as u32) {
            bail!(
                "duplicate standard function name {} at ids {previous} and {id}",
                field.name
            );
        }
    }
    Ok(catalog)
}

fn publish_descriptors<S>(
    state: &mut S,
    mut set: impl FnMut(&mut S, u32, SlotSemantics) -> Result<()>,
    readback: impl FnOnce(&mut S) -> Result<Vec<SlotSemantics>>,
) -> Result<()> {
    let expected = crate::kinds::DESCRIPTORS.to_vec();
    for (index, value) in expected.iter().copied().enumerate() {
        set(state, index as u32, value)?;
    }
    let actual = readback(state)?;
    if actual != expected {
        bail!("DESCRIPTORS exact readback differs from the fixed inventory");
    }
    Ok(())
}

fn publish_async_catalog(ebpf: &mut Ebpf) -> Result<()> {
    let expected = standard_async_catalog()?;
    let mut functions: HashMap<_, FunctionNameKey, u32> = HashMap::try_from(
        ebpf.map_mut("ASYNC_FUNCTIONS")
            .context("ASYNC_FUNCTIONS map")?,
    )?;
    for (&key, &id) in &expected {
        functions.insert(key, id, 0)?;
    }
    let functions: HashMap<_, FunctionNameKey, u32> =
        HashMap::try_from(ebpf.map("ASYNC_FUNCTIONS").context("ASYNC_FUNCTIONS map")?)?;
    let actual = functions.iter().collect::<Result<BTreeMap<_, _>, _>>()?;
    if actual != expected {
        bail!("ASYNC_FUNCTIONS exact readback differs from the standard catalog");
    }
    Ok(())
}

fn publish_attribute_catalog(ebpf: &mut Ebpf, enabled: bool) -> Result<()> {
    let Some(_) = ebpf.map("ATTR_BOOL_BITS") else {
        if enabled {
            bail!("ATTR_BOOL_BITS is missing from the diagnostic eBPF object");
        }
        return Ok(());
    };
    let expected = if enabled {
        p11scope_ebpf_common::attr_bool::TYPES_AND_BITS
            .into_iter()
            .map(|(attribute, bit)| (attribute, 1u32 << bit))
            .collect::<BTreeMap<_, _>>()
    } else {
        BTreeMap::new()
    };
    let mut bits: HashMap<_, u32, u32> = HashMap::try_from(
        ebpf.map_mut("ATTR_BOOL_BITS")
            .context("ATTR_BOOL_BITS map")?,
    )?;
    for (&attribute, &mask) in &expected {
        bits.insert(attribute, mask, 0)?;
    }
    let bits: HashMap<_, u32, u32> =
        HashMap::try_from(ebpf.map("ATTR_BOOL_BITS").context("ATTR_BOOL_BITS map")?)?;
    let actual = bits.iter().collect::<Result<BTreeMap<_, _>, _>>()?;
    if actual != expected {
        bail!("ATTR_BOOL_BITS exact readback differs from the selected policy");
    }
    Ok(())
}

/// Whether freezing this map must wait until the programs are loaded.
///
/// The verifier constant-folds a constant-offset read from a map that is both
/// `BPF_F_RDONLY_PROG` and frozen, and `array_map_direct_value_addr()` opens
/// with `if (map->max_entries != 1) return -ENOTSUPP;`. That internal errno
/// leaves the kernel unchanged, so `BPF_PROG_LOAD` fails with a bare
/// `os error 524` and a verifier log that simply stops at the offending load.
/// Every kernel takes that path -- the check is unchanged from 5.5 through 7.0,
/// and the defect reproduced on 6.8, 6.17 and 7.0 alike, so this is not a
/// version-gated workaround. Freezing after the load avoids it, and
/// every freeze still precedes attachment, so no probe can observe mutable
/// policy. `TAIL_CALLS` and `PAIR_CALLS` are deferred for their own reason:
/// they are populated with program fds that do not exist until the programs
/// load.
fn defers_freeze_until_loaded(name: &str, meta: &ExactMapMetadata) -> bool {
    name == TAIL_POLICY_MAP
        || name == PAIR_POLICY_MAP
        || (matches!(meta.map_type, MapType::Array)
            && meta.flags & BPF_F_RDONLY_PROG != 0
            && meta.max_entries != 1)
}

fn freeze_published_maps(ebpf: &Ebpf) -> Result<()> {
    for (name, meta) in BASE_POLICY_MAPS {
        if defers_freeze_until_loaded(name, &meta) {
            continue;
        }
        let map = ebpf.map(name).with_context(|| format!("{name} map"))?;
        if name == STACK_GUARD_MAP {
            require_empty_stack_guard(map)?;
        }
        freeze_map(name, map)?;
    }
    for (name, meta) in FEATURE_POLICY_MAPS {
        if defers_freeze_until_loaded(name, &meta) {
            continue;
        }
        if let Some(map) = ebpf.map(name) {
            freeze_map(name, map)?;
        }
    }
    Ok(())
}

/// STACK_GUARD only exists to be referenced: its one slot must stay empty so
/// the endpoint programs' opt-out tail call can never jump.
pub(crate) fn require_empty_stack_guard(map: &Map) -> Result<()> {
    match program_array_id(STACK_GUARD_MAP, map, 0)? {
        None => Ok(()),
        Some(id) => bail!("{STACK_GUARD_MAP} must stay empty but slot 0 holds program {id}"),
    }
}

/// PAIR_CALLS under a safe policy is never populated: its one slot must read
/// back empty before the freeze, so the never-attached pair continuation
/// cannot be armed later.
fn require_empty_pair_calls(map: &Map) -> Result<()> {
    match program_array_id(PAIR_POLICY_MAP, map, PAIR_CALLS_SECOND_SLOT)? {
        None => Ok(()),
        Some(id) => {
            bail!(
                "{PAIR_POLICY_MAP} must stay empty under a safe policy but slot holds program {id}"
            )
        }
    }
}

fn validate_runtime_map(
    ebpf: &Ebpf,
    name: &str,
    map_type: MapType,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
) -> Result<()> {
    let map = ebpf.map(name).with_context(|| format!("{name} map"))?;
    let data = match map {
        Map::HashMap(map) | Map::PerCpuArray(map) | Map::RingBuf(map) => map,
        other => bail!("refusing unexpected {name} runtime map variant {other:?}"),
    };
    validate_map_metadata(
        name,
        data,
        map_metadata(map_type, key_size, value_size, max_entries, 0),
    )
}

/// DISCOVERY ring bytes for a cgroup or system capture (RB-2). Every exec
/// and thread-group-leader exit in scope produces one 920-byte discovery
/// record, and the compiled 64 KiB ring holds about 70 of them: a busy host
/// overflowed it between drains and lost the events that admit new
/// processes. 2 MiB holds about 2,260 records, a >30x margin, for 2 MiB of
/// locked kernel memory per capture. A named process keeps the compiled size.
/// `--ring-bytes` still sizes only EVENTS.
pub(crate) const SHARED_SCOPE_DISCOVERY_BYTES: u32 = 2 * 1024 * 1024;

/// The DISCOVERY ring size this scope loads with.
/// The one loader configuration of the capture object, shared by capture
/// sessions and the uretprobe-hazard self-probe (J-DOSSIER#28): vmlinux BTF
/// for the typed task storage, unsupported map types allowed, and the EVENTS
/// and DISCOVERY rings sized at load.
pub(crate) fn load_capture_object(
    btf: &Btf,
    events_bytes: u32,
    discovery_bytes: u32,
) -> std::result::Result<Ebpf, aya::EbpfError> {
    load_capture_object_with_images(btf, events_bytes, discovery_bytes, false)
}

fn load_capture_object_with_images(
    btf: &Btf,
    events_bytes: u32,
    discovery_bytes: u32,
    full_images: bool,
) -> std::result::Result<Ebpf, aya::EbpfError> {
    EbpfLoader::new()
        .btf(Some(btf))
        .allow_unsupported_maps()
        .map_max_entries("EVENTS", events_bytes)
        .map_max_entries("DISCOVERY", discovery_bytes)
        .map_max_entries("IMAGE_CONTINUITY", if full_images { 16_384 } else { 1 })
        .map_max_entries("IMAGE_TGID_INDEX", if full_images { 16_384 } else { 1 })
        .map_max_entries("IMAGE_QUERY_REQUESTS", if full_images { 1_024 } else { 1 })
        .load(crate::EBPF_OBJECT)
}

pub(crate) fn discovery_ring_bytes(scope: &Scope) -> u32 {
    match scope {
        Scope::Pid(_) => p11scope_ebpf_common::DISCOVERY_BYTES,
        Scope::Cgroup { .. } | Scope::System => {
            SHARED_SCOPE_DISCOVERY_BYTES.max(p11scope_ebpf_common::DISCOVERY_BYTES)
        }
    }
}

/// DISCOVERY items moved out of the kernel ring but not yet applied (RB-2).
/// Discovery is *applied* on frames and pause cycles, but the ring is
/// emptied into this FIFO on every capture tick and between startup phases,
/// so a slow frame or a long startup no longer overflows it. Every consumer
/// dequeues through the session, which serves this FIFO first: ring order
/// is preserved and no item is ever dropped here. Staging stops at
/// `CAPACITY`; beyond it records wait in the kernel ring, where overflow is
/// counted by the producer as ring loss.
#[derive(Default)]
pub(crate) struct DiscoveryStage {
    items: std::collections::VecDeque<events::DiscoveryItem>,
}

impl DiscoveryStage {
    /// About 3.7 MiB of 920-byte records, more than one full shared-scope
    /// ring.
    pub(crate) const CAPACITY: usize = 4096;

    /// Moves up to `quantum` items from `next` into the FIFO; returns how
    /// many were staged.
    pub(crate) fn stage(
        &mut self,
        quantum: usize,
        mut next: impl FnMut() -> Option<events::DiscoveryItem>,
    ) -> usize {
        let mut staged = 0;
        while staged < quantum && self.items.len() < Self::CAPACITY {
            let Some(item) = next() else { break };
            self.items.push_back(item);
            staged += 1;
        }
        staged
    }

    pub(crate) fn pop(&mut self) -> Option<events::DiscoveryItem> {
        self.items.pop_front()
    }

    pub(crate) fn take(&mut self) -> Vec<events::DiscoveryItem> {
        self.items.drain(..).collect()
    }

    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }
}

fn validate_runtime_maps(ebpf: &Ebpf, discovery_bytes: u32) -> Result<()> {
    validate_runtime_map(ebpf, "DISCOVERY", MapType::RingBuf, 0, 0, discovery_bytes)?;
    validate_runtime_map(ebpf, "DISCOVERY_STATE", MapType::Hash, 24, 24, 64)?;
    validate_runtime_map(
        ebpf,
        "COUNTERS",
        MapType::PerCpuArray,
        4,
        8,
        p11scope_ebpf_common::DISCOVERY_COUNTER_CELLS,
    )?;
    validate_runtime_map(ebpf, "PAUSE_PIDS", MapType::Hash, 16, 8, 1)
}

fn expected_programs(unsafe_enabled: bool) -> BTreeSet<&'static str> {
    DEFAULT_PROGRAMS
        .into_iter()
        .chain(
            unsafe_enabled
                .then_some(UNSAFE_PROGRAMS)
                .into_iter()
                .flatten(),
        )
        .collect()
}

fn validate_program_inventory(ebpf: &Ebpf, unsafe_enabled: bool) -> Result<()> {
    let mut expected = expected_programs(unsafe_enabled);
    // The continuity hooks are present in every Detailed object but load
    // before deferred freezes, optionally (`InstanceTracking::prepare`).
    expected.extend(INSTANCE_PROGRAMS.iter().map(|(program, _)| *program));
    expected.insert("p11_image_query");
    let actual: BTreeSet<_> = ebpf.programs().map(|(name, _)| name).collect();
    if actual != expected {
        bail!("eBPF program inventory {actual:?} differs from {expected:?}");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionPreparation {
    ValidatePolicy,
    ValidateRuntime,
    ValidateStopGate,
    ValidatePrograms,
    PublishScope,
    PrepareIdentity,
    PublishDescriptors,
    PublishAsync,
    PublishShapes,
    PublishAttributes,
    FreezePublished,
    SelectScope,
    LoadProgram(&'static str),
    LoadImagePrograms,
    FreezeDeferred(&'static str),
    PublishTailCalls,
    PrepareEventsDomain,
}

// BTF and object creation are prerequisites. This is the single loaded-object
// preparation order used by startup; activation cannot bypass a preparation failure.
fn prepare_session_with(
    object_has_unsafe: bool,
    mut operation: impl FnMut(SessionPreparation) -> Result<()>,
) -> Result<()> {
    use SessionPreparation::*;
    for step in [
        ValidatePolicy,
        ValidateRuntime,
        ValidateStopGate,
        ValidatePrograms,
        PublishScope,
        PrepareIdentity,
        PublishDescriptors,
        PublishAsync,
        PublishShapes,
        PublishAttributes,
        FreezePublished,
        SelectScope,
    ] {
        operation(step)?;
    }
    for name in expected_programs(object_has_unsafe) {
        operation(LoadProgram(name))?;
    }
    operation(LoadImagePrograms)?;
    for (name, meta) in BASE_POLICY_MAPS {
        if defers_freeze_until_loaded(name, &meta) && name != TAIL_POLICY_MAP {
            operation(FreezeDeferred(name))?;
        }
    }
    operation(PublishTailCalls)?;
    operation(PrepareEventsDomain)?;
    Ok(())
}

fn activate_after_preparation_with<T>(
    preparation: Result<()>,
    activate: impl FnOnce() -> Result<T>,
) -> Result<T> {
    preparation?;
    activate()
}

fn publish_tail_calls_with<S>(
    state: &mut S,
    worker_id: u32,
    mut write: impl FnMut(&mut S, u32) -> Result<()>,
    mut read: impl FnMut(&mut S, u32) -> Result<Option<u32>>,
    freeze: impl FnOnce(&mut S) -> Result<()>,
) -> Result<()> {
    write(state, TAIL_CALLS_INTERFACE_WORKER_SLOT)?;
    let actual_worker = read(state, TAIL_CALLS_INTERFACE_WORKER_SLOT)?;
    if actual_worker != Some(worker_id) {
        bail!(
            "TAIL_CALLS worker exact readback id {actual_worker:?} differs from loaded program {worker_id}"
        );
    }
    let actual_retired = read(state, TAIL_CALLS_TEMPLATE_SECOND_SLOT)?;
    if actual_retired.is_some() {
        bail!(
            "TAIL_CALLS retired template-second slot reads back {actual_retired:?}, must stay empty"
        );
    }
    freeze(state)
}

fn publish_pair_calls_with<S>(
    state: &mut S,
    second_id: u32,
    mut write: impl FnMut(&mut S, u32) -> Result<()>,
    mut read: impl FnMut(&mut S, u32) -> Result<Option<u32>>,
    freeze: impl FnOnce(&mut S) -> Result<()>,
) -> Result<()> {
    write(state, PAIR_CALLS_SECOND_SLOT)?;
    let actual_second = read(state, PAIR_CALLS_SECOND_SLOT)?;
    if actual_second != Some(second_id) {
        bail!(
            "PAIR_CALLS template-second exact readback id {actual_second:?} differs from loaded program {second_id}"
        );
    }
    freeze(state)
}

fn publish_and_freeze_tail_calls(ebpf: &mut Ebpf, enabled: bool) -> Result<()> {
    let (worker_fd, worker_id) = {
        let worker: &UProbe = ebpf
            .program("interface_list_worker")
            .context("program interface_list_worker missing from object")?
            .try_into()?;
        (worker.fd()?.try_clone()?, worker.info()?.id())
    };
    publish_tail_calls_with(
        ebpf,
        worker_id,
        |ebpf, slot| {
            let mut tails: ProgramArray<_> =
                ProgramArray::try_from(ebpf.map_mut(TAIL_POLICY_MAP).context("TAIL_CALLS map")?)?;
            tails.set(slot, &worker_fd, 0)?;
            Ok(())
        },
        |ebpf, slot| {
            let map = ebpf.map(TAIL_POLICY_MAP).context("TAIL_CALLS map")?;
            program_array_id(TAIL_POLICY_MAP, map, slot)
        },
        |ebpf| {
            let map = ebpf.map(TAIL_POLICY_MAP).context("TAIL_CALLS map")?;
            freeze_map(TAIL_POLICY_MAP, map)
        },
    )?;
    if !enabled {
        // The unsafe object under a safe policy still carries PAIR_CALLS:
        // prove it empty and freeze it so the never-attached pair
        // continuation cannot be armed later. Default and Inventory objects
        // have no such map (validate_policy_maps proved it absent).
        if let Some(map) = ebpf.map(PAIR_POLICY_MAP) {
            require_empty_pair_calls(map)?;
            freeze_map(PAIR_POLICY_MAP, map)?;
        }
        return Ok(());
    }
    let (second_fd, second_id) = {
        let second: &UProbe = ebpf
            .program("p11_entry_template_second")
            .context("program p11_entry_template_second missing from object")?
            .try_into()?;
        (second.fd()?.try_clone()?, second.info()?.id())
    };
    publish_pair_calls_with(
        ebpf,
        second_id,
        |ebpf, slot| {
            let mut pairs: ProgramArray<_> =
                ProgramArray::try_from(ebpf.map_mut(PAIR_POLICY_MAP).context("PAIR_CALLS map")?)?;
            pairs.set(slot, &second_fd, 0)?;
            Ok(())
        },
        |ebpf, slot| {
            let map = ebpf.map(PAIR_POLICY_MAP).context("PAIR_CALLS map")?;
            program_array_id(PAIR_POLICY_MAP, map, slot)
        },
        |ebpf| {
            let map = ebpf.map(PAIR_POLICY_MAP).context("PAIR_CALLS map")?;
            freeze_map(PAIR_POLICY_MAP, map)
        },
    )
}

/// A kernel/environment that cannot load or attach BPF programs at all
/// fails somewhere in `start_inner` below (map creation, program load,
/// or the mechanism registry step never reaches that far) — never at
/// the per-slot attach loop, which is reached only after those succeed.
/// Every realistic cause at that point is an unsupported-environment
/// one, so every early failure gets the same actionable hint appended,
/// naming the concrete things to check instead of leaving a bare
/// syscall error for the operator to diagnose alone.
pub(crate) const UNSUPPORTED_ENV_HINT: &str = "hint: this usually means the environment cannot load or \
attach BPF programs at all — missing CAP_BPF and/or CAP_SYS_ADMIN (or root), a kernel \
lockdown mode, a kernel below the supported floor (>= 5.15), missing BTF \
(/sys/kernel/btf/vmlinux), or a restrictive kernel.perf_event_paranoid sysctl. See \
docs/notes/phase5-unsupported.md for what each looks like when observed. Run \
`p11scope doctor` to see which cause applies on this host.";

fn unsupported_environment_context(error: anyhow::Error) -> anyhow::Error {
    error.context(UNSUPPORTED_ENV_HINT)
}

impl Session {
    pub(crate) const fn capture_policy(&self) -> CapturePolicy {
        self.policy
    }

    /// The session's stop-gate mapping.
    pub(crate) fn stop_gate(&self) -> &StopGate {
        &self.stop_gate
    }

    /// Stamps attach completion with one CLOCK_MONOTONIC read (T2, G-14).
    /// Called once at loop entry, when the session is fully attached; later
    /// discovery-driven attaches do not re-stamp it.
    pub(crate) fn note_attach_complete(&mut self) {
        self.attach_mono_ns = monotonic_ns();
    }

    /// The attach-completion stamp, if the session reached its loop.
    pub(crate) fn attach_mono_ns(&self) -> Option<u64> {
        self.attach_mono_ns
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn start(
        plan: &AttachPlan,
        scope: &Scope,
        objects: &PinnedObjects,
        policy: CapturePolicy,
        pause_generation: Option<OwnedPauseGeneration>,
        ring_bytes: Option<u32>,
        owned_child: Option<&OwnedChild>,
        selection: BackendSelection,
    ) -> Result<Self> {
        // Raise before the first link: every return/entry pair burns fds
        // against RLIMIT_NOFILE, and no tracker (the previous raise site)
        // exists yet at attach time. A 1024 soft limit dies near slot 256.
        let _ = crate::process::raise_nofile();
        let pause_key = pause_key_for(scope, pause_generation.as_ref())?;
        let SessionBackend { backend, fallback } = select_session_backend(
            selection,
            matches!(scope, Scope::Pid(_)),
            multi_functional_probe,
            kernel_multi_pid_filter,
        )?;
        let started = match Self::start_on_backend(
            plan,
            scope,
            objects,
            policy,
            pause_key,
            ring_bytes,
            owned_child,
            backend,
        ) {
            Ok(session) => Ok((session, fallback)),
            Err(error)
                if selection == BackendSelection::Auto
                    && backend == AttachBackend::Multi
                    && error.downcast_ref::<BackendFallbackRequired>().is_some() =>
            {
                // 48-loaded programs cannot single-attach, so an auto multi
                // attempt the kernel refuses is rebuilt on singles at
                // session granularity; the dropped session detaches every
                // probe it created. Forced multi surfaces the refusal.
                // Only the kernel's refusal, never the context chain (which
                // names the provider path).
                let refusal = error
                    .downcast_ref::<BackendFallbackRequired>()
                    .map(ToString::to_string)
                    .unwrap_or_default();
                let reason = format!("the uprobe-multi attach failed: {refusal}");
                Self::start_on_backend(
                    plan,
                    scope,
                    objects,
                    policy,
                    pause_key,
                    ring_bytes,
                    owned_child,
                    AttachBackend::Singles,
                )
                .map(|session| (session, Some(reason)))
            }
            Err(error) => Err(error),
        };
        let (mut session, fallback) = started?;
        session.selection = selection;
        session.backend_fallback = fallback;
        Ok(session)
    }

    /// The receipt is minted from this new Session's maps and retained links;
    /// the caller supplies only the coordinator's move-only accepted subset.
    #[expect(
        dead_code,
        reason = "H3 runtime wiring follows the attested subset gate"
    )]
    pub(crate) fn start_attested(
        subset: crate::inventory_semantics::AttestedSubset,
        scope: &Scope,
        selection: BackendSelection,
    ) -> Result<(Self, AttachedSemanticSet)> {
        let session = Self::start(
            subset.plan(),
            scope,
            subset.pins(),
            CapturePolicy::Allowlisted,
            None,
            None,
            None,
            selection,
        )?;
        let domain = session
            .native_domain()
            .context("Detailed image domain unavailable")?;
        let attached = seal_attached_subset_with(
            subset,
            domain,
            session.policy,
            session.semantic_descriptors(),
            &session.retained_static,
            &session.current_static_sides(),
            |object| {
                session
                    .instance
                    .watched(object)
                    .map(|watched| watched.retained_target())
            },
        )
        .map_err(|reason| anyhow!("attested semantic attachment refused: {reason}"))?;
        Ok((session, attached))
    }

    fn semantic_descriptors(&self) -> Result<Vec<SlotSemantics>> {
        let descriptors: Array<_, SlotSemantics> =
            Array::try_from(self.ebpf.map("DESCRIPTORS").context("DESCRIPTORS map")?)?;
        descriptors
            .iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(anyhow::Error::from)
    }

    fn current_static_sides(&self) -> BTreeSet<StaticEndpoint> {
        self.links
            .iter()
            .flat_map(|link| {
                let side = match link.producer() {
                    ProducerProgram::UProbe(program) => static_probe_side(program),
                    _ => None,
                };
                link.slots()
                    .iter()
                    .filter_map(move |slot| side.map(|side| (*slot, side)))
            })
            .collect()
    }

    #[expect(
        dead_code,
        reason = "H3 runtime wiring follows the attested subset gate"
    )]
    pub(crate) fn validate_semantic_set(&self, attached: &AttachedSemanticSet) -> Result<()> {
        let domain = self
            .native_domain()
            .context("Detailed image domain unavailable")?;
        attached
            .validate_with(
                domain,
                self.policy,
                self.semantic_descriptors(),
                &self.retained_static,
                &self.current_static_sides(),
                |object| {
                    self.instance
                        .watched(object)
                        .map(|watched| watched.retained_target())
                },
            )
            .map_err(|reason| anyhow!("attested semantic attachment refused: {reason}"))
    }

    #[allow(clippy::too_many_arguments)]
    fn start_on_backend(
        plan: &AttachPlan,
        scope: &Scope,
        objects: &PinnedObjects,
        policy: CapturePolicy,
        pause_key: Option<PauseKey>,
        ring_bytes: Option<u32>,
        owned_child: Option<&OwnedChild>,
        backend: AttachBackend,
    ) -> Result<Self> {
        if !objects.check_unchanged().map_err(anyhow::Error::msg)? {
            bail!(
                "a pinned provider object changed before attach; refusing to observe changed bytes"
            );
        }
        let mut session =
            Self::start_inner(scope, policy, pause_key, ring_bytes, owned_child, backend)
                .map_err(unsupported_environment_context)?;
        #[cfg(test)]
        crate::first_use_probe::discovery_loss(
            crate::first_use_probe::DiscoveryStage::LifecycleActive,
            &session,
        );
        session
            .attach_plan(plan, objects)
            .map_err(unsupported_environment_context)?;
        // The lifecycle producers ran through the whole static attach: stage
        // what they produced before the Engine's per-view phases (RB-2).
        session.stage_discovery(crate::discovery::engine::LIVE_DISCOVERY_DRAIN_QUANTUM)?;
        // The error path drops `session`, which detaches every probe.
        if !objects.check_unchanged().map_err(anyhow::Error::msg)? {
            bail!(
                "a pinned provider object changed while attaching; refusing to observe changed bytes"
            );
        }
        #[cfg(test)]
        crate::first_use_probe::discovery_loss(
            crate::first_use_probe::DiscoveryStage::StaticAttached,
            &session,
        );
        Ok(session)
    }

    /// Exercises the real embedded object, policy maps, program inventory,
    /// requested scope, process-creation boundary, and exec/exit links. Dropping the local
    /// session detaches every link before this finite result is returned.
    pub(crate) fn preflight(scope: &Scope) -> Result<AttachPreflight> {
        let session = Self::start_inner(
            scope,
            CapturePolicy::Allowlisted,
            None,
            None,
            None,
            AttachBackend::Singles,
        )?;
        Ok(AttachPreflight {
            lifecycle: session.lifecycle_tracking_unavailable.is_none(),
            scope: session.process_creation_tracking_unavailable.is_none(),
        })
    }

    fn start_inner(
        scope: &Scope,
        policy: CapturePolicy,
        pause_key: Option<PauseKey>,
        ring_bytes: Option<u32>,
        owned_child: Option<&OwnedChild>,
        backend: AttachBackend,
    ) -> Result<Self> {
        if policy.uses_unsafe_decoders() && !cfg!(feature = "unsafe-unvalidated-metadata") {
            bail!("unsafe-unvalidated-metadata policy is absent from this eBPF object");
        }
        // `--ring-bytes` resizes the EVENTS ringbuf at load (aya rounds to a
        // page-sized power of two like libbpf); omission resolves to the
        // baked-in default, which is a no-op override of the ELF value.
        let btf =
            Btf::from_sys_fs().context("loading required vmlinux BTF for typed task_newtask")?;
        let domain = if policy.wants_instance_hooks() {
            Some(capture::NativeDomainId::try_mint()?)
        } else {
            None
        };
        let mut ebpf = load_capture_object_with_images(
            &btf,
            crate::run::resolve_ring_bytes(ring_bytes),
            discovery_ring_bytes(scope),
            policy.wants_instance_hooks(),
        )
        .context("loading BPF object with required task storage")?;
        let object_has_unsafe = cfg!(feature = "unsafe-unvalidated-metadata");
        let unsafe_enabled = object_has_unsafe && policy.uses_unsafe_decoders();
        let generation_token = pause_key.map(|key| key.generation_token);
        let mut uprobe_scope = UProbeScope::AllProcesses;
        let mut stop_gate = None;
        let mut prepared_domain = None;
        let mut prepared_discovery_domain = None;
        let mut root_seed = None;
        let mut image_query = None;
        let mut prepared_instance = None;
        let preparation = prepare_session_with(object_has_unsafe, |step| {
            match step {
                SessionPreparation::ValidatePolicy => {
                    validate_policy_maps(&ebpf, object_has_unsafe)
                        .context("validating exact policy-map metadata")?;
                }
                SessionPreparation::ValidateRuntime => {
                    validate_runtime_maps(&ebpf, discovery_ring_bytes(scope))
                        .context("validating live-discovery runtime maps")?;
                    image_query::prepare_maps(&ebpf, policy.wants_instance_hooks())?;
                }
                SessionPreparation::ValidateStopGate => {
                    validate_stop_gate(&ebpf).context("stop gate unavailable")?;
                    let data = stop_gate_map_data(&ebpf).context("stop gate unavailable")?;
                    stop_gate = Some(
                        StopGate::from_map_fd(data.fd().as_fd())
                            .context("stop gate unavailable")?,
                    );
                }
                SessionPreparation::ValidatePrograms => {
                    validate_program_inventory(&ebpf, object_has_unsafe)
                        .context("validating exact eBPF program inventory")?;
                }
                SessionPreparation::PublishScope => {
                    crate::scope::publish(&mut ebpf, scope, policy, generation_token)
                        .context("publishing scope and capture policy")?;
                    debug_assert!(process_creation_capture_enabled(scope, policy));
                }
                SessionPreparation::PrepareIdentity => {
                    prepare_identity(&mut ebpf, scope, owned_child)
                        .context("preparing required image identity and thread ownership")?;
                }
                SessionPreparation::PublishDescriptors => {
                    let mut semantics: Array<_, SlotSemantics> =
                        Array::try_from(ebpf.map_mut("DESCRIPTORS").context("DESCRIPTORS map")?)?;
                    publish_descriptors(
                        &mut semantics,
                        |semantics, index, value| {
                            semantics.set(index, value, 0).map_err(anyhow::Error::from)
                        },
                        |semantics| {
                            semantics
                                .iter()
                                .collect::<Result<Vec<_>, _>>()
                                .map_err(anyhow::Error::from)
                        },
                    )
                    .context("publishing DESCRIPTORS")?;
                }
                SessionPreparation::PublishAsync => {
                    publish_async_catalog(&mut ebpf).context("publishing ASYNC_FUNCTIONS")?;
                }
                SessionPreparation::PublishShapes => {
                    // Embedded defaults: this binary ships statically and has no
                    // config-file plumbing yet, so `None` is the only reachable
                    // path today. A future task can thread a path through here
                    // without touching the publish-before-attach placement.
                    let registry = MechanismRegistry::load(None)
                        .map_err(|e| anyhow!("loading mechanism registry: {e}"))?;
                    crate::shapes::publish(&mut ebpf, &registry)
                        .context("publishing MECH_SHAPE")?;
                }
                SessionPreparation::PublishAttributes => {
                    publish_attribute_catalog(&mut ebpf, unsafe_enabled)
                        .context("publishing ATTR_BOOL_BITS")?;
                }
                SessionPreparation::FreezePublished => {
                    freeze_published_maps(&ebpf).context("freezing published policy maps")?;
                }
                SessionPreparation::SelectScope => {
                    uprobe_scope = match scope {
                        Scope::Pid(pid) => UProbeScope::OneProcess(
                            std::num::NonZeroU32::new(*pid).context("pid must be non-zero")?,
                        ),
                        // Cgroup and system scoping are enforced in BPF, so the
                        // probe itself is process-wide and the CONFIG bit decides.
                        Scope::Cgroup { .. } | Scope::System => UProbeScope::AllProcesses,
                    };
                }
                SessionPreparation::LoadProgram(prog_name) => {
                    if matches!(prog_name, "sched_process_exec" | "sched_process_exit") {
                        let prog: &mut RawTracePoint = ebpf
                            .program_mut(prog_name)
                            .with_context(|| format!("program {prog_name} missing from object"))?
                            .try_into()?;
                        prog.load()
                            .with_context(|| format!("loading required raw {prog_name}"))?;
                    } else if prog_name == "task_newtask" {
                        let prog: &mut BtfTracePoint = ebpf
                            .program_mut(prog_name)
                            .context("program task_newtask missing from object")?
                            .try_into()?;
                        prog.load("task_newtask", &btf)
                            .context("loading required typed task_newtask")?;
                    } else {
                        let prog: &mut UProbe = ebpf
                            .program_mut(prog_name)
                            .with_context(|| format!("program {prog_name} missing from object"))?
                            .try_into()?;
                        if loads_with_multi_flag(backend, prog_name) {
                            prog.load_multi()
                                .with_context(|| format!("loading {prog_name} for multi attach"))?;
                        } else {
                            prog.load()
                                .with_context(|| format!("loading {prog_name}"))?;
                        }
                    }
                }
                SessionPreparation::LoadImagePrograms => {
                    let query_refusal = match domain {
                        Some(domain) => {
                            match image_query::ImageQueryOwner::load(&mut ebpf, &btf, domain) {
                                Ok(owner) => {
                                    image_query = Some(owner);
                                    None
                                }
                                Err(error) => Some(format!("{error:#}")),
                            }
                        }
                        None => None,
                    };
                    prepared_instance = Some(InstanceTracking::prepare(
                        &mut ebpf,
                        &btf,
                        policy,
                        query_refusal,
                    ));
                }
                SessionPreparation::FreezeDeferred(name) => {
                    freeze_map(name, ebpf.map(name).with_context(|| format!("{name} map"))?)
                        .with_context(|| format!("freezing {name}"))?;
                }
                SessionPreparation::PublishTailCalls => {
                    publish_and_freeze_tail_calls(&mut ebpf, unsafe_enabled)
                        .context("publishing and freezing tail calls")?;
                }
                SessionPreparation::PrepareEventsDomain => {
                    let events_domain = events::EventsDomain::from_events(&ebpf)?;
                    let discovery_domain = events::DiscoveryDomain::from_discovery(&ebpf)?;
                    root_seed = owned_child.map(|child| RootSeed {
                        pin: child.seed_pin(),
                        domain: events_domain.clone(),
                    });
                    prepared_domain = Some(events_domain);
                    prepared_discovery_domain = Some(discovery_domain);
                }
            }
            Ok(())
        });
        let (events_domain, discovery_domain, links) =
            activate_after_preparation_with(preparation, || {
                let events_domain =
                    prepared_domain.expect("preparation established the events domain");
                let discovery_domain = prepared_discovery_domain
                    .expect("preparation established the discovery domain");
                let links = attach_lifecycle_with(
                    &mut ebpf,
                    |ebpf, program| {
                        if program == "task_newtask" {
                            let hook: &mut BtfTracePoint = ebpf
                                .program_mut(program)
                                .context("required task_newtask program")?
                                .try_into()?;
                            Ok(RegisteredLink::BtfTracePoint {
                                program,
                                id: hook.attach()?,
                            })
                        } else {
                            let hook: &mut RawTracePoint = ebpf
                                .program_mut(program)
                                .with_context(|| format!("required raw {program} program"))?
                                .try_into()?;
                            Ok(RegisteredLink::RawTracePoint {
                                program,
                                id: hook.attach(program)?,
                            })
                        }
                    },
                    |ebpf, _, link| detach_registered_link(ebpf, link),
                )?;
                Ok((events_domain, discovery_domain, links))
            })?;
        // After the mandatory lifecycle links and before any endpoint link
        // (ordering I1). A failure refuses instance routing, not capture.
        // Metrics sessions skip the hooks (Task 1d overhead gate): they
        // never join per-call records, so their slots stay unmapped.
        let trace_coverage =
            detailed_identity::TraceCoverage::after_activation(scope, monotonic_ns());
        let image_coverage = image_query::CoverageControl::new(&ebpf)?;
        let instance = InstanceTracking::start(
            &mut ebpf,
            &image_coverage,
            prepared_instance.expect("preparation established image program load result"),
        );

        Ok(Self {
            stop_gate: stop_gate.expect("preparation established the stop gate"),
            image_coverage,
            image_query,
            ebpf,
            events_domain,
            events_consumer: None,
            discovery_domain,
            trace_coverage,
            trace_proof: None,
            discovery_consumer: None,
            discovery_staged: DiscoveryStage::default(),
            root_seed,
            attach_failures: vec![],
            detach_failures: vec![],
            producers_detached: false,
            detach_wall_ms: 0,
            attach_mono_ns: None,
            successful_static: BTreeSet::new(),
            dynamic_attach_evidence: DynamicAttachEvidence::default(),
            policy,
            backend,
            selection: BackendSelection::Auto,
            backend_fallback: None,
            uprobe_scope,
            pause_key,
            lifecycle_tracking_unavailable: None,
            process_creation_tracking_unavailable: None,
            retained_static: BTreeMap::new(),
            links,
            instance,
            cleanup_worker: Some(CleanupWorker::pre_start()),
        })
    }

    pub(crate) fn counter_snapshot(&self) -> Result<CounterSnapshot> {
        let counters: PerCpuArray<_, u64> =
            PerCpuArray::try_from(self.ebpf.map("COUNTERS").context("COUNTERS map")?)?;
        let read = |index| -> Result<u64> {
            Ok(counters
                .get(&index, 0)?
                .iter()
                .copied()
                .fold(0u64, u64::saturating_add))
        };
        let evidence: PerCpuArray<_, u64> =
            PerCpuArray::try_from(self.ebpf.map("EVIDENCE").context("EVIDENCE map")?)?;
        let abi_refusals = evidence
            .get(&EVIDENCE_ABI_REFUSALS, 0)?
            .iter()
            .copied()
            .fold(0u64, u64::saturating_add);
        counter_snapshot_with(read, abi_refusals)
    }

    pub(crate) fn preflight_targets(
        &self,
        targets: &[Slot],
        objects: &PinnedObjects,
    ) -> Result<()> {
        attachment_admission(&self.detach_failures, !targets.is_empty())?;
        if !objects.check_unchanged().map_err(anyhow::Error::msg)? {
            bail!("a pinned provider object changed before live attachment");
        }
        for target in targets {
            objects
                .attach_path_for(target.object)
                .map_err(anyhow::Error::msg)?;
            objects
                .abi_for(target.object)
                .ok_or_else(|| anyhow!("object {:?} has no retained target ABI", target.object))?;
            let _ = attach_cookie(target.index, target.descriptor_index);
        }
        Ok(())
    }

    pub(crate) fn attach_dynamic_loader(
        &mut self,
        context: LoaderContextId,
        pid: u32,
        object: PinnedObjectId,
        file_offset: u64,
        cookie: u64,
        objects: &PinnedObjects,
    ) -> std::result::Result<bool, DynamicLoaderAttachFailure> {
        if !objects
            .check_unchanged()
            .map_err(|error| DynamicLoaderAttachFailure::Provenance(anyhow!(error)))?
        {
            return Err(DynamicLoaderAttachFailure::Provenance(anyhow!(
                "a pinned loader object changed before dynamic attach"
            )));
        }
        if self.has_dynamic_link(context, "dl_debug_state", object, file_offset, cookie) {
            return Ok(false);
        }
        attachment_admission(&self.detach_failures, true)
            .map_err(DynamicLoaderAttachFailure::Registry)?;
        let path = objects
            .attach_path_for(object)
            .map_err(|error| DynamicLoaderAttachFailure::Registry(anyhow!(error)))?;
        let point = UProbeAttachPoint {
            location: UProbeAttachLocation::AbsoluteOffset(file_offset),
            cookie: Some(cookie),
        };
        let program = "dl_debug_state";
        let probe: &mut UProbe = self
            .ebpf
            .program_mut(program)
            .ok_or(DynamicLoaderAttachFailure::ProgramMissing)?
            .try_into()
            .map_err(|error| DynamicLoaderAttachFailure::ProgramType(anyhow::Error::from(error)))?;
        let scope = UProbeScope::OneProcess(
            std::num::NonZeroU32::new(pid).ok_or(DynamicLoaderAttachFailure::InvalidPid)?,
        );
        match record_dynamic_attach_with(probe, &mut self.dynamic_attach_evidence, |probe| {
            probe.attach([point], &path, scope)
        }) {
            Ok(id) => {
                self.links.push(RegisteredLink::DynamicUProbe {
                    program,
                    context,
                    object,
                    file_offset,
                    cookie,
                    abi: None,
                    id,
                });
                Ok(true)
            }
            Err(error) => {
                let message = format!(
                    "{program} at object {:?}+{file_offset:#x}: {}",
                    object,
                    error_chain(&error)
                );
                Err(DynamicLoaderAttachFailure::KernelUnavailable(anyhow!(
                    message
                )))
            }
        }
    }

    pub(crate) fn attach_dynamic_export(
        &mut self,
        context: LoaderContextId,
        pid: u32,
        target: (PinnedObjectId, u64),
        cookie: u64,
        abi: HookAbi,
        objects: &PinnedObjects,
    ) -> Result<(bool, Option<u64>)> {
        let (object, file_offset) = target;
        if !objects.check_unchanged().map_err(anyhow::Error::msg)? {
            bail!("a pinned export object changed before dynamic attach");
        }
        let (entry_program, return_program) = export_programs(abi);
        if self.has_dynamic_link(context, return_program, object, file_offset, cookie) {
            return Ok((false, None));
        }
        attachment_admission(&self.detach_failures, true)?;
        let path = objects
            .attach_path_for(object)
            .map_err(anyhow::Error::msg)?;
        let point = || UProbeAttachPoint {
            location: UProbeAttachLocation::AbsoluteOffset(file_offset),
            cookie: Some(cookie),
        };
        let scope = UProbeScope::OneProcess(
            std::num::NonZeroU32::new(pid).context("dynamic export PID must be non-zero")?,
        );
        let detach_failures = &mut self.detach_failures;
        let (entry_id, return_id) = attach_dynamic_export_with(
            &mut self.ebpf,
            &mut self.dynamic_attach_evidence,
            |ebpf, is_return| {
                let program = if is_return {
                    return_program
                } else {
                    entry_program
                };
                let probe: &mut UProbe = ebpf
                    .program_mut(program)
                    .with_context(|| format!("program {program} missing from object"))?
                    .try_into()?;
                probe.attach([point()], &path, scope).map_err(|error| {
                    anyhow!(
                        "{program} at object {:?}+{file_offset:#x}: {}",
                        object,
                        error_chain(&error)
                    )
                })
            },
            |ebpf, return_id| {
                let result = ebpf
                    .program_mut(return_program)
                    .with_context(|| {
                        format!("program {return_program} missing during partial detach")
                    })
                    .and_then(|program| {
                        let probe: &mut UProbe = program.try_into()?;
                        probe.detach(return_id).map_err(Into::into)
                    });
                if let Err(error) = result {
                    detach_failures.push(format!("detaching partial {return_program}: {error:#}"));
                }
            },
        )?;
        // Register entry first so selective and terminal drains stop new state
        // before removing the matching return consumer.
        self.links.extend(
            [(entry_program, entry_id), (return_program, return_id)].map(|(program, id)| {
                RegisteredLink::DynamicUProbe {
                    program,
                    context,
                    object,
                    file_offset,
                    cookie,
                    abi: Some(abi),
                    id,
                }
            }),
        );
        Ok((true, monotonic_ns()))
    }

    pub(crate) fn has_dynamic_export(
        &self,
        context: LoaderContextId,
        target: (PinnedObjectId, u64),
        cookie: u64,
        abi: HookAbi,
    ) -> bool {
        let (_, return_program) = export_programs(abi);
        self.has_dynamic_link(context, return_program, target.0, target.1, cookie)
    }

    fn has_dynamic_link(
        &self,
        context: LoaderContextId,
        program: &'static str,
        object: PinnedObjectId,
        file_offset: u64,
        cookie: u64,
    ) -> bool {
        self.links.iter().any(|link| {
            matches!(
                link,
                RegisteredLink::DynamicUProbe {
                    program: linked_program,
                    context: linked_context,
                    object: linked_object,
                    file_offset: linked_offset,
                    cookie: linked_cookie,
                    ..
                } if *linked_program == program
                    && *linked_context == context
                    && *linked_object == object
                    && *linked_offset == file_offset
                    && *linked_cookie == cookie
            )
        })
    }

    pub(crate) fn detach_dynamic_context(
        &mut self,
        context: LoaderContextId,
    ) -> (Vec<DynamicExportIdentity>, bool) {
        let snapshot = dynamic_export_snapshot_with(&self.links, context, |link| match link {
            RegisteredLink::DynamicUProbe {
                context,
                object,
                file_offset,
                cookie,
                abi,
                ..
            } => (
                *context,
                abi.map(|abi| DynamicExportIdentity {
                    object: *object,
                    file_offset: *file_offset,
                    cookie: *cookie,
                    abi,
                }),
            ),
            RegisteredLink::UProbe { .. }
            | RegisteredLink::MultiUProbe { .. }
            | RegisteredLink::RawTracePoint { .. }
            | RegisteredLink::BtfTracePoint { .. }
            | RegisteredLink::DiagnosticUProbe { .. } => (context, None),
        });
        let failures = self.detach_failures.len();
        let _ = self.detach_links(|link| link.context() == Some(context));
        (snapshot, self.detach_failures.len() != failures)
    }

    /// Attaches every active target that this session has not already linked.
    /// The static `start` wrapper calls this once; live discovery supplies the
    /// same complete plan snapshot later without reloading or republishing maps.
    pub(crate) fn attach_plan(&mut self, plan: &AttachPlan, objects: &PinnedObjects) -> Result<()> {
        if !objects.check_unchanged().map_err(anyhow::Error::msg)? {
            bail!(
                "a pinned provider object changed before attach; refusing to observe changed bytes"
            );
        }
        let targets: Vec<_> = plan
            .slots
            .iter()
            .filter(|slot| plan.is_active(slot.index) && !self.has_slot_link(slot.index))
            .cloned()
            .collect();
        let _ = self.attach_targets(&targets, objects)?;
        if !objects.check_unchanged().map_err(anyhow::Error::msg)? {
            bail!(
                "a pinned provider object changed while attaching; refusing to observe changed bytes"
            );
        }
        Ok(())
    }

    /// Attaches a finite set of fresh slots and returns those whose return link
    /// could not be established. An entry is never attempted for such a slot.
    pub(crate) fn attach_targets(
        &mut self,
        targets: &[Slot],
        objects: &PinnedObjects,
    ) -> Result<TargetAttachResult> {
        let mut requested = BTreeSet::new();
        if let Some(slot) = targets.iter().find(|slot| !requested.insert(slot.index)) {
            bail!("slot {} was requested for attachment twice", slot.index);
        }
        if let Some(slot) = targets.iter().find(|slot| self.has_slot_link(slot.index)) {
            bail!("slot {} already has an owned probe link", slot.index);
        }
        attachment_admission(&self.detach_failures, !targets.is_empty())?;
        let attach_targets: BTreeMap<_, _> = targets
            .iter()
            // By capture-local pinned ID only. There is deliberately no by-path
            // fallback: a target pathname can name a different object here.
            .map(|slot| {
                let path = objects
                    .attach_path_for(slot.object)
                    .map_err(anyhow::Error::msg)?;
                let abi = objects.abi_for(slot.object).ok_or_else(|| {
                    anyhow!("object {:?} has no retained target ABI", slot.object)
                })?;
                Ok((slot.index, (path, abi)))
            })
            .collect::<Result<_>>()?;
        // Ordering I1: watched-file keys and SLOT_FILE before any link.
        self.instance
            .prepare_targets(&mut self.ebpf, targets, objects);
        let scope = self.uprobe_scope;
        let outcome = if self.backend == AttachBackend::Multi {
            self.attach_targets_multi(targets, &attach_targets)?
        } else {
            let ebpf = &mut self.ebpf;
            let links = &mut self.links;
            attach_targets_with(
                targets,
                self.policy,
                cfg!(feature = "unsafe-unvalidated-metadata"),
                |slot| {
                    Ok(attach_targets
                        .get(&slot.index)
                        .expect("every selected target has retained pinned facts")
                        .1)
                },
                |program, slot, point| {
                    let path = &attach_targets
                        .get(&slot.index)
                        .expect("every selected target has retained pinned facts")
                        .0;
                    let prog: &mut UProbe = ebpf
                        .program_mut(program)
                        .with_context(|| format!("program {program} missing from object"))?
                        .try_into()?;
                    match prog.attach([point], path, scope) {
                        Ok(id) => {
                            links.push(RegisteredLink::UProbe {
                                program,
                                slot: slot.index,
                                id,
                            });
                            Ok(())
                        }
                        Err(error) => Err(static_attach_error(program, slot, error)),
                    }
                },
                |_| monotonic_ns(),
            )?
        };
        let AttachOutcome {
            successful,
            failures,
            completed,
            exhausted: _,
        } = outcome;
        retain_from_successful(
            &mut self.retained_static,
            targets,
            &attach_targets,
            &successful,
        );
        self.successful_static.extend(successful);
        let failed: Vec<_> = failures.iter().map(|(slot, _)| *slot).collect();
        self.attach_failures.extend(failures);
        #[cfg(test)]
        crate::first_use_probe::attached(&self.events_domain, targets, objects, &completed);
        Ok((failed, completed))
    }

    /// Multi half of [`Session::attach_targets`]: regroups the targets by
    /// (attach path, entry program) and attaches one return link plus one
    /// entry link per group over the 48-loaded twins, target-named under
    /// PID scope (probe-gated) and pid-wide otherwise, with the in-BPF
    /// scope filter as defence in depth (see [`multi_link_pid`]). Late
    /// joiners (live discovery) form their own groups and attach as
    /// additional links; the Task 2.3 rebuild covers retirement and
    /// replacement, not coalescing live groups. A kernel without multi
    /// support aborts with
    /// [`BackendFallbackRequired`] (downcastable through anyhow) so
    /// `start` can rebuild the session on singles.
    fn attach_targets_multi(
        &mut self,
        targets: &[Slot],
        attach_targets: &BTreeMap<u32, (PathBuf, ElfAbi)>,
    ) -> Result<AttachOutcome> {
        let groups = group_static_slots(
            targets,
            self.policy,
            cfg!(feature = "unsafe-unvalidated-metadata"),
            attach_targets,
        );
        let mut programs: BTreeSet<&'static str> =
            groups.iter().map(|group| group.entry_program).collect();
        programs.insert("p11_return");
        let mut prog_fds = BTreeMap::new();
        for program in programs {
            prog_fds.insert(program, multi_prog_fd(&mut self.ebpf, program)?);
        }
        let pid = multi_link_pid(self.uprobe_scope);
        let (bundles, outcome) = attach_target_groups_with(
            &groups,
            |_| monotonic_ns(),
            |program, path, slice, is_return| {
                let prog_fd = prog_fds
                    .get(program)
                    .copied()
                    .expect("every group side pre-resolved its program fd");
                let (offsets, cookies): (Vec<u64>, Vec<u64>) = slice.iter().copied().unzip();
                attach_group(prog_fd, pid, path, &offsets, &cookies, is_return)
            },
        )?;
        for bundle in bundles {
            self.links.push(RegisteredLink::MultiUProbe {
                program: bundle.program,
                slots: bundle.slots,
                fds: bundle.links,
            });
        }
        Ok(outcome)
    }

    /// Applies the attachment half of a descriptor downgrade after the caller
    /// has detached the old links and synchronized semantic consumers. A failed
    /// replacement cannot fall back to the frozen descriptor it replaced.
    pub fn replace_targets(
        &mut self,
        plan: &mut AttachPlan,
        replace: &[Slot],
        objects: &PinnedObjects,
    ) -> Result<ReplacementOutcome> {
        if let Some(slot) = replace.iter().find(|slot| self.has_slot_link(slot.index)) {
            bail!(
                "replacement slot {} still has an old link; detach and synchronize it before reattach",
                slot.index
            );
        }
        let (failed, completed) = match self.attach_targets(replace, objects) {
            Ok(outcome) => outcome,
            Err(error) => {
                for slot in replace {
                    self.attach_failures
                        .push((slot.index, format!("replacement attach: {error:#}")));
                    plan.deactivate(slot.index);
                }
                return Err(error);
            }
        };
        let failed: BTreeSet<_> = failed.into_iter().collect();
        let failed_slots: Vec<_> = replace
            .iter()
            .filter(|slot| failed.contains(&slot.index))
            .cloned()
            .collect();
        // An entry failure still leaves a successful return link behind. Remove
        // it before retiring the slot so failed replacement evidence is exact.
        let detach = self.detach_slots(&failed_slots);
        for slot in &failed_slots {
            plan.deactivate(slot.index);
        }
        let (failed_detach, rebuild) = match detach {
            Ok(rebuild) => (false, rebuild),
            Err(_) => (true, DetachOutcome::default()),
        };
        Ok(ReplacementOutcome {
            completed,
            failed_detach,
            rebuild,
        })
    }

    /// Detaches all slot links selected by a finite retirement/replacement
    /// delta, rebuilding partially covered multi groups. Each detach attempt
    /// is made even if an earlier one failed; the report carries per-member
    /// rebuild evidence for the caller to apply.
    pub fn detach_slots(&mut self, slots: &[Slot]) -> Result<DetachOutcome> {
        let requested: BTreeSet<_> = slots.iter().map(|slot| slot.index).collect();
        let Some(affected) = plan_group_rebuild(&self.links, &requested) else {
            let detached = self.detach_links(|link| match link {
                // A group link drops only with all its members.
                RegisteredLink::MultiUProbe { slots, .. } => {
                    !slots.is_empty() && slots.iter().all(|slot| requested.contains(slot))
                }
                _ => link.slots().iter().any(|slot| requested.contains(slot)),
            });
            prune_linkless_retained(&mut self.retained_static, &self.links);
            return detached.map(|()| DetachOutcome::default());
        };
        self.rebuild_affected_groups(&requested, &affected)
    }

    /// Explicit multi-group rebuild for a partially covered retirement:
    /// determine every affected member from retained facts, detach old
    /// entries before returns, then reattach surviving siblings returns
    /// before entries. A detach failure aborts before any reattach — a
    /// maybe-live old link must never overlap a replacement, and the
    /// ownership uncertainty blocks additions through the existing
    /// [`attachment_admission`] refusal. Reattach evidence is per member:
    /// only fully paired survivors count as multi-attached.
    fn rebuild_affected_groups(
        &mut self,
        requested: &BTreeSet<u32>,
        affected: &BTreeSet<u32>,
    ) -> Result<DetachOutcome> {
        let mut survivors = Vec::new();
        let mut missing = Vec::new();
        for member in affected.difference(requested) {
            match self.retained_static.get(member) {
                Some(target) => survivors.push(target.clone()),
                None => missing.push(*member),
            }
        }
        // Regroup and resolve program fds before the first link mutation:
        // a failure here leaves every old link untouched.
        let regrouped: Vec<Slot> = survivors.iter().map(|target| target.slot.clone()).collect();
        #[cfg(test)]
        if !regrouped.is_empty() {
            crate::first_use_probe::unsupported_rebuild();
        }
        let targets: BTreeMap<u32, (PathBuf, ElfAbi)> = survivors
            .iter()
            .map(|target| (target.slot.index, (target.path.clone(), target.abi)))
            .collect();
        let groups = group_static_slots(
            &regrouped,
            self.policy,
            cfg!(feature = "unsafe-unvalidated-metadata"),
            &targets,
        );
        let rebuilt_groups = affected_group_count(&self.links, affected);
        let mut programs: BTreeSet<&'static str> =
            groups.iter().map(|group| group.entry_program).collect();
        programs.insert("p11_return");
        let mut prog_fds = BTreeMap::new();
        for program in programs {
            prog_fds.insert(program, multi_prog_fd(&mut self.ebpf, program)?);
        }
        self.detach_links(|link| match link {
            RegisteredLink::MultiUProbe { slots, .. } => {
                slots.iter().any(|slot| affected.contains(slot))
            }
            _ => link.slots().iter().any(|slot| requested.contains(slot)),
        })?;
        prune_linkless_retained(&mut self.retained_static, &self.links);
        let pid = multi_link_pid(self.uprobe_scope);
        let (bundles, outcome) = reattach_rebuilt_groups_with(
            &groups,
            |_| monotonic_ns(),
            |program, path, slice, is_return| {
                let prog_fd = prog_fds
                    .get(program)
                    .copied()
                    .expect("every rebuilt side pre-resolved its program fd");
                let (offsets, cookies): (Vec<u64>, Vec<u64>) = slice.iter().copied().unzip();
                attach_group(prog_fd, pid, path, &offsets, &cookies, is_return)
            },
            // Closing the owned fds detaches the rolled-back links.
            drop,
        );
        for bundle in bundles {
            self.links.push(RegisteredLink::MultiUProbe {
                program: bundle.program,
                slots: bundle.slots,
                fds: bundle.links,
            });
        }
        let AttachOutcome {
            successful,
            failures: mut rebuild_failures,
            completed: recompleted,
            exhausted: _,
        } = outcome;
        self.successful_static.extend(successful);
        for member in missing {
            rebuild_failures.push((
                member,
                format!(
                    "slot {member} was not reattached: \
                     no retained attach facts for a live group member"
                ),
            ));
        }
        self.attach_failures
            .extend(rebuild_failures.iter().cloned());
        prune_linkless_retained(&mut self.retained_static, &self.links);
        Ok(DetachOutcome {
            recompleted,
            rebuild_failures,
            rebuilt_groups,
        })
    }

    /// Detach every event/map producer while keeping the maps and ring reader
    /// available for a best-effort terminal drain and snapshot. Entry probes
    /// go first so fewer calls are stranded before the return probes are
    /// removed last. Kernel detach does not wait for callbacks already running
    /// on another CPU; callers must not claim that the terminal drain is final.
    pub fn detach_producers(&mut self) -> Result<()> {
        self.detach_producers_driven(|| false, &mut std::io::stderr())
    }

    /// Move every producer link out of Aya into the background cleanup
    /// worker, print progress to `out` about once a second until it joins,
    /// then report. `second_signal` interrupts the wait: the progress and
    /// "cleanup incomplete" are printed and this returns
    /// [`CleanupInterrupted`] for the caller to propagate (exit 130) — the
    /// kernel finishes the remaining closes at exit.
    pub(crate) fn detach_producers_driven(
        &mut self,
        second_signal: impl Fn() -> bool,
        out: &mut dyn std::io::Write,
    ) -> Result<()> {
        let start = std::time::Instant::now();
        let had_links = !self.links.is_empty();
        let mut first_error = None;
        if had_links {
            let mut owned = Vec::new();
            let mut transfer_failed = 0;
            for link in std::mem::take(&mut self.links) {
                let producer = link.producer();
                match take_owned_links(&mut self.ebpf, link) {
                    Ok(links) => owned.extend(links.into_iter().map(|link| (link, producer))),
                    Err(error) => {
                        transfer_failed += 1;
                        let message = format!("{error:#}");
                        self.detach_failures.push(message.clone());
                        if first_error.is_none() {
                            first_error = Some(anyhow!(message));
                        }
                    }
                }
            }
            let worker = self.take_cleanup_worker();
            worker.note_transfer_failed(transfer_failed);
            worker.submit(owned, DetachOrder);
            // A second SIGINT abandons the wait: the worker keeps closing
            // in the background and the kernel finishes at exit. The typed
            // outcome travels up the stop path to `main` (exit 130).
            let failures = cleanup_worker::settle_cleanup_exit(drive_cleanup(
                worker,
                second_signal,
                out,
                std::time::Duration::from_secs(1),
            ))?;
            for failure in failures {
                if first_error.is_none() {
                    first_error = Some(anyhow!(failure.clone()));
                }
                self.detach_failures.push(failure);
            }
        } else {
            let _ = (second_signal, out);
        }
        self.detach_wall_ms =
            record_detach_wall_ms(self.detach_wall_ms, had_links, detach_wall_ms_since(start));
        finish_producer_detach(
            &mut self.producers_detached,
            &self.detach_failures,
            first_error.map_or(Ok(()), Err),
        )
    }

    fn take_cleanup_worker(&mut self) -> CleanupWorker {
        self.cleanup_worker
            .take()
            .unwrap_or_else(CleanupWorker::pre_start)
    }

    /// Wall time the producer detach took, in whole milliseconds; zero
    /// when detach never ran. Reports read this before publication (the
    /// terminal callback publishes before the producers detach), so they
    /// carry pre-publication detach work only.
    pub(crate) fn detach_wall_ms(&self) -> u64 {
        self.detach_wall_ms
    }

    /// The bound the next `EVENTS` poll gets — see `events::poll_quantum`.
    pub fn live_poll_quantum(&self) -> Option<usize> {
        events::poll_quantum(self.producers_detached)
    }

    /// Whether every producer detached: live drains re-poll within the
    /// tick budget, the terminal drain takes one explicitly bounded poll.
    pub(crate) fn producers_detached(&self) -> bool {
        self.producers_detached
    }

    pub(crate) fn take_root_seed(&mut self) -> Option<RootSeed> {
        self.root_seed.take()
    }

    fn has_slot_link(&self, slot: u32) -> bool {
        links_cover_slot(&self.links, slot)
    }

    fn detach_links(&mut self, mut select: impl FnMut(&RegisteredLink) -> bool) -> Result<()> {
        let mut selected = Vec::new();
        let mut retained = Vec::new();
        for link in std::mem::take(&mut self.links) {
            if select(&link) {
                selected.push(link);
            } else {
                retained.push(link);
            }
        }
        self.links = retained;

        let mut first_error = None;
        for error in detach_selected_with(
            selected
                .into_iter()
                .map(|link| (link.producer(), link))
                .collect(),
            |link| self.detach_link(link),
        ) {
            let message = format!("{error:#}");
            self.detach_failures.push(message.clone());
            if first_error.is_none() {
                first_error = Some(anyhow!(message));
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn detach_link(&mut self, link: RegisteredLink) -> Result<()> {
        detach_registered_link(&mut self.ebpf, link)
    }

    pub(crate) fn diagnostic() -> Result<Self> {
        Self::start_inner(
            &Scope::Pid(std::process::id()),
            CapturePolicy::Allowlisted,
            None,
            None,
            None,
            AttachBackend::Singles,
        )
    }

    pub(crate) fn attach_diagnostic_probe(&mut self, path: &Path, offset: u64) -> Result<()> {
        attachment_admission(&self.detach_failures, true)?;
        let probe: &mut UProbe = self
            .ebpf
            .program_mut("p11_entry")
            .context("diagnostic p11_entry program")?
            .try_into()?;
        let id = probe.attach(
            [UProbeAttachPoint {
                location: UProbeAttachLocation::AbsoluteOffset(offset),
                cookie: None,
            }],
            path,
            UProbeScope::CallingProcess,
        )?;
        self.links.push(RegisteredLink::DiagnosticUProbe {
            program: "p11_entry",
            id,
        });
        Ok(())
    }

    pub(crate) fn events_domain(&self) -> events::EventsDomain {
        self.events_domain.clone()
    }

    /// The session's single retained `EVENTS` consumer, with exclusive
    /// `&mut` access: one cursor and one malformed total across every
    /// live, root-tail and terminal poll. Built once on first drain; the
    /// reader owns its mappings and never borrows this session's `Ebpf`.
    pub fn event_drain(&mut self) -> Result<&mut events::OwnedDrain> {
        if self.events_consumer.is_none() {
            let consumer = events::OwnedDrain::for_session(&self.ebpf, &self.events_domain)?;
            self.events_consumer = Some(consumer);
            self.wire_trace_consumers()
                .map_err(|reason| anyhow!("private trace proof: {reason:?}"))?;
        }
        self.events_consumer
            .as_mut()
            .context("retained EVENTS consumer vanished after creation")
    }

    /// Borrow the EVENTS map descriptor for readiness waits. The idle
    /// wait polls this fd (wake on data or timeout); draining still
    /// goes through `event_drain`, the single consumer.
    pub(crate) fn events_readiness_fd(&self) -> BorrowedFd<'_> {
        self.events_domain.as_fd()
    }

    /// Borrow the DISCOVERY map descriptor for readiness waits, beside
    /// EVENTS: a filling discovery ring wakes the idle loop to stage it.
    pub(crate) fn discovery_readiness_fd(&self) -> BorrowedFd<'_> {
        self.discovery_domain.as_fd()
    }

    /// The descriptors the idle wait polls: EVENTS always, and DISCOVERY
    /// while the staging FIFO has room. A full FIFO leaves the discovery
    /// ring readable until the next frame applies it; polling it then would
    /// spin the loop.
    pub(crate) fn readiness_fds(&self) -> Vec<BorrowedFd<'_>> {
        let mut fds = vec![self.events_readiness_fd()];
        if self.discovery_staged.len() < DiscoveryStage::CAPACITY {
            fds.push(self.discovery_readiness_fd());
        }
        fds
    }

    /// Moves up to `quantum` DISCOVERY items off the kernel ring into the
    /// session's FIFO without applying any (RB-2); returns how many.
    pub(crate) fn stage_discovery(&mut self, quantum: usize) -> Result<usize> {
        self.ensure_discovery_consumer()?;
        let consumer = self
            .discovery_consumer
            .as_mut()
            .context("retained DISCOVERY consumer vanished after creation")?;
        Ok(self.discovery_staged.stage(quantum, || consumer.dequeue()))
    }

    /// Every staged item, in ring order, leaving the FIFO empty.
    pub(crate) fn take_staged_discovery(&mut self) -> Vec<events::DiscoveryItem> {
        self.discovery_staged.take()
    }

    pub(crate) fn discovery_dequeue(&mut self) -> Result<Option<events::DiscoveryItem>> {
        if let Some(item) = self.discovery_staged.pop() {
            return Ok(Some(item));
        }
        if self.discovery_consumer.is_none() {
            let consumer =
                events::OwnedDiscoveryDrain::for_session(&self.ebpf, &self.discovery_domain)?;
            self.discovery_consumer = Some(consumer);
            self.wire_trace_consumers()
                .map_err(|reason| anyhow!("private trace proof: {reason:?}"))?;
        }
        Ok(self
            .discovery_consumer
            .as_mut()
            .context("retained DISCOVERY consumer vanished after creation")?
            .dequeue())
    }

    fn ensure_events_consumer(&mut self) -> Result<()> {
        if self.events_consumer.is_none() {
            let consumer = events::OwnedDrain::for_session(&self.ebpf, &self.events_domain)?;
            self.events_consumer = Some(consumer);
            self.wire_trace_consumers()
                .map_err(|reason| anyhow!("private trace proof: {reason:?}"))?;
        }
        Ok(())
    }

    fn ensure_discovery_consumer(&mut self) -> Result<()> {
        if self.discovery_consumer.is_none() {
            let consumer =
                events::OwnedDiscoveryDrain::for_session(&self.ebpf, &self.discovery_domain)?;
            self.discovery_consumer = Some(consumer);
            self.wire_trace_consumers()
                .map_err(|reason| anyhow!("private trace proof: {reason:?}"))?;
        }
        Ok(())
    }

    /// Polls the stop gate for quiescence for up to `budget`, servicing
    /// the EVENTS/DISCOVERY drains between polls. The caller requests the
    /// stop first (immediately, before the stop marker); `None` for
    /// `service_events` skips the EVENTS consumer entirely (`--mode
    /// metrics` never drains that ring). Field-split borrows keep the
    /// gate shared while the service closures drain through the two
    /// retained consumers.
    pub(crate) fn quiesce_terminal(
        &mut self,
        budget: std::time::Duration,
        mut service_events: Option<impl FnMut(&mut events::OwnedDrain)>,
        mut service_discovery: impl FnMut(&mut events::OwnedDiscoveryDrain),
        now: impl FnMut() -> std::time::Instant,
    ) -> Result<crate::run::StopState> {
        if service_events.is_some() {
            self.ensure_events_consumer()?;
        }
        self.ensure_discovery_consumer()?;
        let gate = &self.stop_gate;
        let mut events = self.events_consumer.as_mut();
        let discovery = self
            .discovery_consumer
            .as_mut()
            .context("retained DISCOVERY consumer vanished after creation")?;
        Ok(crate::run::quiesce_with(
            gate,
            budget,
            || {
                if let Some(service) = service_events.as_mut() {
                    service(
                        events
                            .as_deref_mut()
                            .expect("EVENTS service without an EVENTS consumer"),
                    );
                }
                service_discovery(&mut *discovery);
            },
            now,
        ))
    }

    /// The EVENTS ring's current positions, for reading the Q stop
    /// position after quiescence is proven.
    pub(crate) fn event_drain_positions(
        &mut self,
    ) -> Result<aya::maps::ring_buf::RingBufPositions> {
        self.ensure_events_consumer()?;
        Ok(events::event_drain_positions(
            self.events_consumer
                .as_ref()
                .context("retained EVENTS consumer vanished after creation")?,
        ))
    }

    /// The DISCOVERY ring's current positions, for reading the Q stop
    /// position after quiescence is proven.
    pub(crate) fn discovery_positions(&mut self) -> Result<aya::maps::ring_buf::RingBufPositions> {
        self.ensure_discovery_consumer()?;
        Ok(events::discovery_drain_positions(
            self.discovery_consumer
                .as_ref()
                .context("retained DISCOVERY consumer vanished after creation")?,
        ))
    }

    /// One DISCOVERY quantum bounded by the Q `stop` position: the
    /// collected records, the malformed count, and the
    /// `(post_q_record, backlog)` contract of the bounded drains.
    pub(crate) fn collect_discovery_to_position(
        &mut self,
        stop: usize,
        quantum: usize,
    ) -> Result<(Vec<p11scope_ebpf_common::DiscoveryRecord>, u64, bool, bool)> {
        self.ensure_discovery_consumer()?;
        let mut records = Vec::new();
        let mut malformed = 0u64;
        // Staged items left the ring before the stop was requested, so they
        // precede Q and come first.
        let mut left = quantum;
        while left > 0 {
            let Some(item) = self.discovery_staged.pop() else {
                break;
            };
            match item {
                events::DiscoveryItem::Record(record) => records.push(record),
                events::DiscoveryItem::Malformed => malformed = malformed.saturating_add(1),
            }
            left -= 1;
        }
        if left == 0 {
            return Ok((records, malformed, false, true));
        }
        let consumer = self
            .discovery_consumer
            .as_mut()
            .context("retained DISCOVERY consumer vanished after creation")?;
        let (post_q_record, backlog) =
            events::poll_discovery_to_position(consumer, stop, Some(left), |item| {
                match item {
                    events::DiscoveryItem::Record(record) => records.push(record),
                    events::DiscoveryItem::Malformed => {
                        malformed = malformed.saturating_add(1);
                    }
                }
                std::ops::ControlFlow::Continue(())
            })?;
        Ok((records, malformed, post_q_record, backlog))
    }

    #[allow(dead_code)] // Task 8 drives the Task 7 pause coordinator.
    pub(crate) fn arm_pause(&mut self) -> Result<()> {
        let key = self
            .pause_key
            .context("this session has no owned pause generation")?;
        let pid_filter: HashMap<_, u32, u64> =
            HashMap::try_from(self.ebpf.map("PID_FILTER").context("PID_FILTER map")?)?;
        let token = pid_filter
            .get(&key.tgid, 0)
            .context("reading back owned PID_FILTER generation token")?;
        if token == 0 || token != key.generation_token {
            bail!("PID_FILTER generation token changed; refusing to arm pause");
        }

        let mut pauses: HashMap<_, PauseKey, u64> =
            HashMap::try_from(self.ebpf.map_mut("PAUSE_PIDS").context("PAUSE_PIDS map")?)?;
        pauses.insert(key, PAUSE_ARMED, 0)?;
        let actual = match pauses.get(&key, 0) {
            Ok(actual) => actual,
            Err(error) => {
                let _ = pauses.remove(&key);
                return Err(error).context("reading back PAUSE_PIDS authorization");
            }
        };
        if actual != PAUSE_ARMED {
            pauses
                .remove(&key)
                .context("removing inexact PAUSE_PIDS authorization")?;
            bail!("PAUSE_PIDS exact full-key readback differs from ARMED");
        }
        Ok(())
    }

    #[allow(dead_code)] // Task 8 drives the Task 7 pause coordinator.
    pub(crate) fn pause_state(&self) -> Result<Option<u64>> {
        let key = self
            .pause_key
            .context("this session has no owned pause generation")?;
        let pauses: HashMap<_, PauseKey, u64> =
            HashMap::try_from(self.ebpf.map("PAUSE_PIDS").context("PAUSE_PIDS map")?)?;
        match pauses.get(&key, 0) {
            Ok(state) => Ok(Some(state)),
            Err(MapError::KeyNotFound) => Ok(None),
            Err(error) => Err(error).context("reading PAUSE_PIDS authorization"),
        }
    }

    #[allow(dead_code)] // Task 8 drives the Task 7 pause coordinator.
    pub(crate) fn remove_pause(&mut self) -> Result<Option<u64>> {
        let key = self
            .pause_key
            .context("this session has no owned pause generation")?;
        let mut pauses: HashMap<_, PauseKey, u64> =
            HashMap::try_from(self.ebpf.map_mut("PAUSE_PIDS").context("PAUSE_PIDS map")?)?;
        let state = match pauses.get(&key, 0) {
            Ok(state) => Some(state),
            Err(MapError::KeyNotFound) => None,
            Err(error) => return Err(error).context("reading PAUSE_PIDS before removal"),
        };
        if state.is_some() {
            pauses
                .remove(&key)
                .context("removing PAUSE_PIDS authorization")?;
        }
        Ok(state)
    }

    /// Attach points that failed — reported as an evidence gap, never
    /// silently treated as zero calls.
    pub fn attach_failures(&self) -> &[(u32, String)] {
        &self.attach_failures
    }

    /// Detach failures remain available after the terminal best-effort drain.
    pub fn detach_failures(&self) -> &[String] {
        &self.detach_failures
    }

    /// Task 3 Stage A instance tracking state (hooks, watched files).
    #[allow(dead_code)] // Task 6 native seam (DR-T3A-1); privileged gates today.
    pub(crate) fn instance_tracking(&self) -> &InstanceTracking {
        &self.instance
    }

    /// Readers over the continuity maps.
    #[allow(dead_code)] // Task 6 native seam (DR-T3A-1); privileged gates today.
    pub(crate) fn instance_maps(&self) -> InstanceMaps<'_> {
        InstanceMaps { ebpf: &self.ebpf }
    }

    /// Exact metadata retained by the current owned static attachment, never
    /// reconstructed from a pathname or caller-supplied offset.
    pub(crate) fn instance_endpoint(&self, slot: u32) -> Option<crate::semantic_capture::Endpoint> {
        let target = self.retained_static.get(&slot)?;
        let watched = self.instance.watched(target.slot.object)?;
        Some(crate::semantic_capture::Endpoint {
            object: target.slot.object,
            file_slot: watched.file_slot,
            offset: target.slot.file_offset,
        })
    }

    /// The continuity hooks' run/miss statistics.
    #[allow(dead_code)] // Task 6 native seam (DR-T3A-1); privileged gates today.
    pub(crate) fn instance_hook_stats(&self) -> Result<Vec<(&'static str, HookStats)>> {
        self.instance.hook_stats(&self.ebpf)
    }

    pub(crate) fn lifecycle_tracking_unavailable(&self) -> Option<&str> {
        self.lifecycle_tracking_unavailable.as_deref()
    }

    pub(crate) fn process_creation_tracking_unavailable(&self) -> Option<&str> {
        self.process_creation_tracking_unavailable.as_deref()
    }

    /// Lifetime successful static endpoints (2 per fully-attached slot).
    pub fn attached_probes(&self) -> usize {
        self.successful_static.len()
    }

    /// True when static endpoints attached through multi group links.
    /// The backend is fixed at load, so this is exact: every static
    /// endpoint in the session shares it.
    pub fn static_multi_attached(&self) -> bool {
        self.backend == AttachBackend::Multi && !self.successful_static.is_empty()
    }

    /// The profile lane's `evidence.attach_backend` (DR-CLASSIC-PID0).
    pub(crate) fn attach_backend_evidence(&self) -> crate::render::AttachBackendEvidence {
        crate::render::AttachBackendEvidence {
            selection: match self.selection {
                BackendSelection::Auto => "auto",
                BackendSelection::Multi => "multi",
                BackendSelection::Singles => "singles",
            },
            fallback: self.backend_fallback.clone(),
            scope_filter: self.scope_filter(),
        }
    }

    /// Why an `auto` session runs per-offset links, else `None`.
    pub(crate) fn backend_fallback(&self) -> Option<&str> {
        self.backend_fallback.as_deref()
    }

    /// Under PID scope, what keeps other processes out of the static
    /// probes besides the in-BPF PID guard: `kernel-pid+bpf` (uprobe-multi
    /// links name the target) or `perf-task+bpf` (each per-offset link is
    /// bound to the target's task); `None` under cgroup and system scope.
    pub(crate) fn scope_filter(&self) -> Option<&'static str> {
        match (self.uprobe_scope, self.backend) {
            (UProbeScope::OneProcess(_), AttachBackend::Multi) => Some("kernel-pid+bpf"),
            (UProbeScope::OneProcess(_), AttachBackend::Singles) => Some("perf-task+bpf"),
            (UProbeScope::AllProcesses | UProbeScope::CallingProcess, _) => None,
        }
    }

    pub(crate) fn dynamic_per_offset_attached(&self) -> bool {
        self.dynamic_attach_evidence.successful()
    }
}

/// Move one registered link out of Aya into worker-owned values, without
/// closing anything: singles become `FdLink`s via `take_link` plus
/// `into_fd_links()` (Inventory precedent `activation.rs:433-466`), multis
/// move their fds. A single uprobe id can expand to several `FdLink`s.
/// A link that is not fd-backed detaches synchronously on drop instead
/// and still counts as closed. On the normal detach path the transfer
/// runs after publication, never before a held child's resume; the
/// `Drop` fallback reuses this transfer best-effort and offers no
/// ordering guarantee.
fn take_owned_links(ebpf: &mut Ebpf, link: RegisteredLink) -> Result<Vec<OwnedLink>> {
    match link {
        RegisteredLink::MultiUProbe { fds, .. } => Ok(vec![OwnedLink::Multi(fds)]),
        RegisteredLink::UProbe { program, id, .. }
        | RegisteredLink::DiagnosticUProbe { program, id } => (|| {
            let probe: &mut UProbe = ebpf
                .program_mut(program)
                .with_context(|| format!("program {program} missing during detach"))?
                .try_into()?;
            let taken = probe
                .take_link(id)
                .with_context(|| format!("detaching {program}"))?;
            match taken.into_fd_links() {
                Ok(links) => Ok(links.into_iter().map(OwnedLink::Fd).collect()),
                Err(link) => {
                    drop(link);
                    Ok(Vec::new())
                }
            }
        })(),
        RegisteredLink::RawTracePoint { program, id } => (|| {
            let tracepoint: &mut RawTracePoint = ebpf
                .program_mut(program)
                .with_context(|| format!("program {program} missing during detach"))?
                .try_into()?;
            let taken = tracepoint
                .take_link(id)
                .with_context(|| format!("detaching {program}"))?;
            Ok(vec![OwnedLink::Fd(taken.into())])
        })(),
        RegisteredLink::BtfTracePoint { program, id } => (|| {
            let tracepoint: &mut BtfTracePoint = ebpf
                .program_mut(program)
                .with_context(|| format!("program {program} missing during detach"))?
                .try_into()?;
            let taken = tracepoint
                .take_link(id)
                .with_context(|| format!("detaching {program}"))?;
            Ok(vec![OwnedLink::Fd(taken.into())])
        })(),
        RegisteredLink::DynamicUProbe { program, id, .. } => (|| {
            let probe: &mut UProbe = ebpf
                .program_mut(program)
                .with_context(|| format!("program {program} missing during detach"))?
                .try_into()?;
            let taken = probe
                .take_link(id)
                .with_context(|| format!("detaching {program}"))?;
            match taken.into_fd_links() {
                Ok(links) => Ok(links.into_iter().map(OwnedLink::Fd).collect()),
                Err(link) => {
                    drop(link);
                    Ok(Vec::new())
                }
            }
        })(),
    }
}

fn detach_registered_link(ebpf: &mut Ebpf, link: RegisteredLink) -> Result<()> {
    match link {
        // Detach is drop: closing the last link fd detaches the kernel
        // link, so moving the fds out here releases every leaf.
        RegisteredLink::MultiUProbe { fds, .. } => {
            drop(fds);
            Ok(())
        }
        RegisteredLink::UProbe { program, id, .. }
        | RegisteredLink::DiagnosticUProbe { program, id } => (|| {
            let probe: &mut UProbe = ebpf
                .program_mut(program)
                .with_context(|| format!("program {program} missing during detach"))?
                .try_into()?;
            probe
                .detach(id)
                .with_context(|| format!("detaching {program}"))
        })(),
        RegisteredLink::RawTracePoint { program, id } => (|| {
            let tracepoint: &mut RawTracePoint = ebpf
                .program_mut(program)
                .with_context(|| format!("program {program} missing during detach"))?
                .try_into()?;
            tracepoint
                .detach(id)
                .with_context(|| format!("detaching {program}"))
        })(),
        RegisteredLink::BtfTracePoint { program, id } => (|| {
            let tracepoint: &mut BtfTracePoint = ebpf
                .program_mut(program)
                .with_context(|| format!("program {program} missing during detach"))?
                .try_into()?;
            tracepoint
                .detach(id)
                .with_context(|| format!("detaching {program}"))
        })(),
        RegisteredLink::DynamicUProbe { program, id, .. } => (|| {
            let probe: &mut UProbe = ebpf
                .program_mut(program)
                .with_context(|| format!("program {program} missing during detach"))?
                .try_into()?;
            probe
                .detach(id)
                .with_context(|| format!("detaching {program}"))
        })(),
    }
}

fn detach_wall_ms_since(start: std::time::Instant) -> u64 {
    start.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

/// Next recorded detach wall time: a detach that finds no links keeps
/// the real teardown's time instead of overwriting it with ~0 ms.
pub(crate) fn record_detach_wall_ms(previous_ms: u64, detached_any: bool, elapsed_ms: u64) -> u64 {
    if detached_any {
        elapsed_ms
    } else {
        previous_ms
    }
}

fn finish_producer_detach(
    detached: &mut bool,
    failures: &[String],
    result: Result<()>,
) -> Result<()> {
    *detached = result.is_ok() && failures.is_empty();
    result?;
    if !failures.is_empty() {
        bail!(
            "producer detach ownership remains uncertain: {}",
            failures.join("; ")
        );
    }
    Ok(())
}

impl Drop for Session {
    fn drop(&mut self) {
        // Refuse continuity before closing any owned producer/hook link.
        self.image_coverage.fail();
        // Never block on a worker-owned link: leftovers move to the
        // worker and close in the background (at process exit the kernel
        // finishes). Evidence is best-effort; there is no caller to fail.
        if self.links.is_empty() {
            return;
        }
        let mut owned = Vec::new();
        for link in std::mem::take(&mut self.links) {
            let producer = link.producer();
            if let Ok(links) = take_owned_links(&mut self.ebpf, link) {
                owned.extend(links.into_iter().map(|link| (link, producer)));
            }
        }
        let worker = self.take_cleanup_worker();
        worker.submit(owned, DetachOrder);
        drop(worker);
    }
}

#[cfg(test)]
mod capture_policy {
    use super::CapturePolicy;

    #[test]
    fn capture_policies_have_distinct_bits_and_visible_behavior() {
        let policies = [
            (CapturePolicy::Allowlisted, "allowlisted", true, false),
            (
                CapturePolicy::UnsafeUnvalidatedMetadata,
                "unsafe-unvalidated-metadata",
                true,
                true,
            ),
            (CapturePolicy::AggregateOnly, "aggregate-only", false, false),
        ];

        for (policy, privacy_mode, uses_events, uses_unsafe_decoders) in policies {
            assert_eq!(policy.privacy_mode(), privacy_mode);
            assert_eq!(policy.uses_events(), uses_events);
            assert_eq!(policy.uses_unsafe_decoders(), uses_unsafe_decoders);
        }
        assert_ne!(
            CapturePolicy::Allowlisted.config_bit(),
            CapturePolicy::UnsafeUnvalidatedMetadata.config_bit()
        );
        assert_ne!(
            CapturePolicy::Allowlisted.config_bit(),
            CapturePolicy::AggregateOnly.config_bit()
        );
        assert_ne!(
            CapturePolicy::UnsafeUnvalidatedMetadata.config_bit(),
            CapturePolicy::AggregateOnly.config_bit()
        );
    }

    #[test]
    fn instance_hooks_attach_only_where_per_call_records_join() {
        // Task 1d overhead gate: the mapping hooks cost ~280-415 ns per
        // event system-wide, so only policies that join per-call records
        // to load instances (profile/trace) attach them; metrics
        // (aggregate-only) never drains a per-call record and skips them.
        assert!(CapturePolicy::Allowlisted.wants_instance_hooks());
        assert!(CapturePolicy::UnsafeUnvalidatedMetadata.wants_instance_hooks());
        assert!(!CapturePolicy::AggregateOnly.wants_instance_hooks());
    }
}

#[cfg(test)]
mod policy_output {
    use super::CapturePolicy;

    #[test]
    fn cli_policy_matrix_is_safe_by_default_and_double_gates_unsafe() {
        assert_eq!(
            CapturePolicy::from_cli("profile", false, false).unwrap(),
            CapturePolicy::Allowlisted
        );
        assert_eq!(
            CapturePolicy::from_cli("profile", false, true).unwrap(),
            CapturePolicy::Allowlisted
        );
        assert_eq!(
            CapturePolicy::from_cli("trace", false, true).unwrap(),
            CapturePolicy::Allowlisted
        );
        assert_eq!(
            CapturePolicy::from_cli("metrics", false, false).unwrap(),
            CapturePolicy::AggregateOnly
        );
        assert_eq!(
            CapturePolicy::from_cli("metrics", false, true).unwrap(),
            CapturePolicy::AggregateOnly
        );
        assert_eq!(
            CapturePolicy::from_cli("profile", true, true).unwrap(),
            CapturePolicy::UnsafeUnvalidatedMetadata
        );
        assert!(CapturePolicy::from_cli("profile", true, false).is_err());
        assert!(CapturePolicy::from_cli("metrics", true, true).is_err());
        assert!(CapturePolicy::from_cli("discover", true, true).is_err());
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn backport_multi_sections_parse_for_uprobe_twins() {
        use std::str::FromStr as _;
        for section in [
            "uprobe/p11_entry",
            "uprobe.s/p11_entry",
            "uprobe.multi/p11_entry",
            "uprobe.multi.s/p11_entry",
            "uretprobe/p11_return",
            "uretprobe.s/p11_return",
            "uretprobe.multi/p11_return",
            "uretprobe.multi.s/p11_return",
        ] {
            assert!(
                aya_obj::ProgramSection::from_str(section).is_ok(),
                "{section} must parse"
            );
        }
    }

    #[test]
    fn backport_multi_flag_set_only_for_multi_sections() {
        use aya_obj::ProgramSection;
        use std::str::FromStr as _;
        for (section, sleepable, multi, ret) in [
            ("uprobe/p11_entry", false, false, false),
            ("uprobe.s/p11_entry", true, false, false),
            ("uprobe.multi/p11_entry", false, true, false),
            ("uprobe.multi.s/p11_entry", true, true, false),
            ("uretprobe/p11_return", false, false, true),
            ("uretprobe.s/p11_return", true, false, true),
            ("uretprobe.multi/p11_return", false, true, true),
            ("uretprobe.multi.s/p11_return", true, true, true),
        ] {
            let parsed = ProgramSection::from_str(section).unwrap();
            let (actual_sleepable, actual_multi, actual_ret) = match parsed {
                ProgramSection::UProbe {
                    sleepable, multi, ..
                } => (sleepable, multi, false),
                ProgramSection::URetProbe {
                    sleepable, multi, ..
                } => (sleepable, multi, true),
                _ => panic!("{section} parsed as {parsed:?}"),
            };
            assert_eq!(
                (actual_sleepable, actual_multi, actual_ret),
                (sleepable, multi, ret),
                "{section}"
            );
        }
    }

    #[test]
    fn backend_selection_parses_the_three_documented_values() {
        use super::BackendSelection;
        assert_eq!(
            BackendSelection::from_cli("auto").unwrap(),
            BackendSelection::Auto
        );
        assert_eq!(
            BackendSelection::from_cli("multi").unwrap(),
            BackendSelection::Multi
        );
        assert_eq!(
            BackendSelection::from_cli("singles").unwrap(),
            BackendSelection::Singles
        );
        assert_eq!(BackendSelection::default(), BackendSelection::Auto);
        for bad in ["", "MULTI", "uprobe-multi", "per-offset", "multi "] {
            assert!(
                BackendSelection::from_cli(bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn multi_policy_follows_the_6_9_floor_and_rejects_garbage() {
        use super::multi_allowed_on;
        for release in [
            "6.9.0",
            "6.9.12-1-generic",
            "6.10.0",
            "6.15.0-100-generic",
            "7.0.0",
        ] {
            assert!(multi_allowed_on(release), "{release} must allow multi");
        }
        for release in ["6.8.0", "6.6.0", "6.5.0-15-generic", "5.15.0", "4.19.0", ""] {
            assert!(!multi_allowed_on(release), "{release:?} must stay singles");
        }
        for release in ["not-a-release", "6", "6.x", "v6.9.0-"] {
            assert!(
                !multi_allowed_on(release),
                "{release:?} must conservatively stay singles"
            );
        }
    }

    #[test]
    fn multi_links_name_the_pid_target_and_pid_zero_only_scope_wide() {
        // DR-CLASSIC-PID0: a PID-scoped uprobe-multi link names the target
        // (never pid 0); cgroup and system scope stay pid-wide behind the
        // in-BPF scope gate.
        use aya::programs::uprobe::UProbeScope;
        let target = std::num::NonZeroU32::new(4242).unwrap();
        assert_eq!(super::multi_link_pid(UProbeScope::OneProcess(target)), 4242);
        assert_eq!(super::multi_link_pid(UProbeScope::AllProcesses), 0);
    }

    #[test]
    fn only_static_endpoint_twins_and_pair_continuation_take_the_multi_load_flag() {
        use super::AttachBackend;
        use super::loads_with_multi_flag;
        for program in [
            "p11_return",
            "p11_entry",
            "p11_entry_ia32",
            "p11_entry_template",
            "p11_entry_template_types",
            "p11_entry_template_pair",
            "p11_entry_template_second",
        ] {
            assert!(
                loads_with_multi_flag(AttachBackend::Multi, program),
                "{program} must load with the multi flag"
            );
            assert!(
                !loads_with_multi_flag(AttachBackend::Singles, program),
                "{program} must load plain under singles"
            );
        }
        for program in [
            "dl_debug_state",
            "function_list_entry",
            "sched_process_exec",
            "task_newtask",
            "interface_list_worker",
            "no_such_program",
        ] {
            assert!(
                !loads_with_multi_flag(AttachBackend::Multi, program),
                "{program} must stay on singles (dynamic/diag/lifecycle)"
            );
        }
    }

    #[test]
    fn static_probe_side_routes_entry_variants_and_return() {
        use super::ProbeSide;
        use super::static_probe_side;
        assert_eq!(static_probe_side("p11_return"), Some(ProbeSide::Return));
        for program in [
            "p11_entry",
            "p11_entry_ia32",
            "p11_entry_template",
            "p11_entry_template_types",
            "p11_entry_template_pair",
        ] {
            assert_eq!(static_probe_side(program), Some(ProbeSide::Entry));
        }
        assert_eq!(static_probe_side("task_newtask"), None);
        // The continuation loads with its caller's attach type but is never
        // attached: it is only installed into PAIR_CALLS.
        assert_eq!(static_probe_side("p11_entry_template_second"), None);
    }

    /// DR-CLASSIC-PID0: the classic backend follows functional probes:
    /// PID scope takes uprobe-multi only where the pid-filter probe proves
    /// the kernel filter, else per-offset links with its reason (auto) or a
    /// refusal (forced multi); other scopes follow the multi probe; forced
    /// singles probes nothing.
    #[test]
    fn backend_selection_follows_the_probes_never_the_kernel_version() {
        use super::{AttachBackend, BackendSelection, SessionBackend, select_session_backend};
        let ok = || Ok(());
        let refused = |reason: &'static str| move || Err(reason.to_string());
        let never = || -> std::result::Result<(), String> { panic!("probed") };
        let pick = |backend, fallback: Option<&str>| SessionBackend {
            backend,
            fallback: fallback.map(str::to_string),
        };
        // Singles: no probe at all.
        for pid_scope in [false, true] {
            assert_eq!(
                select_session_backend(BackendSelection::Singles, pid_scope, never, never).unwrap(),
                pick(AttachBackend::Singles, None)
            );
        }
        // PID scope: the pid-filter probe alone decides.
        assert_eq!(
            select_session_backend(BackendSelection::Auto, true, never, ok).unwrap(),
            pick(AttachBackend::Multi, None)
        );
        let fallback =
            select_session_backend(BackendSelection::Auto, true, never, refused("own=1")).unwrap();
        assert_eq!(fallback.backend, AttachBackend::Singles);
        assert!(
            fallback
                .fallback
                .as_deref()
                .is_some_and(|reason| reason.contains("pid filter") && reason.contains("own=1")),
            "{fallback:?}"
        );
        assert_eq!(
            select_session_backend(BackendSelection::Multi, true, never, ok).unwrap(),
            pick(AttachBackend::Multi, None)
        );
        let forced =
            select_session_backend(BackendSelection::Multi, true, never, refused("EINVAL"))
                .unwrap_err()
                .to_string();
        assert!(
            forced.contains("pid filter") && forced.contains("EINVAL"),
            "{forced}"
        );
        // Other scopes: the multi probe decides auto; forced multi attempts.
        assert_eq!(
            select_session_backend(BackendSelection::Auto, false, ok, never).unwrap(),
            pick(AttachBackend::Multi, None)
        );
        let fallback =
            select_session_backend(BackendSelection::Auto, false, refused("EINVAL"), never)
                .unwrap();
        assert_eq!(fallback.backend, AttachBackend::Singles);
        assert!(
            fallback.fallback.as_deref().is_some_and(
                |reason| reason.contains("functional probe") && reason.contains("EINVAL")
            ),
            "{fallback:?}"
        );
        assert_eq!(
            select_session_backend(BackendSelection::Multi, false, never, never).unwrap(),
            pick(AttachBackend::Multi, None)
        );
    }

    #[test]
    fn detach_wall_time_is_measured_in_whole_milliseconds() {
        let now = std::time::Instant::now();
        assert_eq!(super::detach_wall_ms_since(now), 0);
        let past = now - std::time::Duration::from_millis(61_234);
        assert_eq!(super::detach_wall_ms_since(past), 61_234);
    }

    #[test]
    fn empty_detach_keeps_the_real_teardown_time() {
        // The `60e7500` retention: the post-publication detach closes the
        // real links, then any later detach finds no links and must not
        // overwrite the real teardown's time with ~0 ms.
        assert_eq!(super::record_detach_wall_ms(0, true, 120), 120);
        assert_eq!(super::record_detach_wall_ms(120, false, 0), 120);
    }

    #[test]
    fn owner_limit_uses_exact_loaded_start_shape() {
        for (capacity, limit) in [(16_384, 16_448), (1, 65)] {
            let actual = map_metadata(MapType::Hash, 16, 288, capacity, 0);
            assert_eq!(owner_limit_for_start(actual).unwrap(), limit);
            for bad in [
                ExactMapMetadata {
                    map_type: MapType::Array,
                    ..actual
                },
                ExactMapMetadata {
                    key_size: 17,
                    ..actual
                },
                ExactMapMetadata {
                    value_size: 289,
                    ..actual
                },
                ExactMapMetadata {
                    max_entries: 2,
                    ..actual
                },
                ExactMapMetadata { flags: 1, ..actual },
            ] {
                assert!(owner_limit_for_start(bad).is_err());
            }
        }
    }
    #[test]
    fn identity_metadata_checks_every_tuple_field() {
        for (name, expected) in IDENTITY_MAPS {
            compare_map_metadata(name, expected, expected).unwrap();
            for actual in [
                ExactMapMetadata {
                    map_type: MapType::Hash,
                    ..expected
                },
                ExactMapMetadata {
                    key_size: expected.key_size + 1,
                    ..expected
                },
                ExactMapMetadata {
                    value_size: expected.value_size + 1,
                    ..expected
                },
                ExactMapMetadata {
                    max_entries: expected.max_entries + 1,
                    ..expected
                },
                ExactMapMetadata {
                    flags: expected.flags ^ 1,
                    ..expected
                },
            ] {
                assert!(
                    compare_map_metadata(name, actual, expected).is_err(),
                    "{name}: {actual:?}"
                );
            }
        }
    }

    #[test]
    fn stop_gate_validation_rejects_wrong_type_flags_or_width() {
        let expected = map_metadata(MapType::Array, 4, 8, 1, BPF_F_MMAPABLE);
        compare_map_metadata("STOP_GATE", expected, expected).unwrap();
        for actual in [
            map_metadata(MapType::Hash, 4, 8, 1, BPF_F_MMAPABLE),
            map_metadata(MapType::Array, 4, 8, 1, 0),
            map_metadata(MapType::Array, 4, 4, 1, BPF_F_MMAPABLE),
            map_metadata(MapType::Array, 4, 8, 2, BPF_F_MMAPABLE),
        ] {
            assert!(
                compare_map_metadata("STOP_GATE", actual, expected).is_err(),
                "{actual:?}"
            );
        }
    }

    #[test]
    fn identity_inventory_rejects_missing_extra_and_wrong_variants() {
        let valid = [
            ("TASK_COOKIE", true),
            ("THREAD_OWNER", true),
            ("ROOT_AFFILIATION", true),
            ("COOKIE_CTL", false),
            ("OWNER_CTL", false),
            ("ROOT_CTL", false),
        ];
        validate_identity_inventory(valid.into_iter()).unwrap();
        for index in [0, 1, 2] {
            assert!(
                validate_identity_inventory(
                    valid
                        .into_iter()
                        .enumerate()
                        .filter_map(|(i, v)| (i != index).then_some(v))
                )
                .is_err()
            );
            let mut wrong = valid;
            wrong[index].1 = false;
            assert!(validate_identity_inventory(wrong.into_iter()).is_err());
        }
        for extra in ["OTHER", "COOKIE_CTL", "OWNER_CTL", "ROOT_CTL"] {
            assert!(validate_identity_inventory(valid.into_iter().chain([(extra, true)])).is_err());
        }
    }

    #[test]
    fn identity_preparation_stops_at_every_write_readback_and_freeze_failure() {
        let mut expected = Vec::new();
        prepare_identity_with(true, |step| {
            expected.push(step);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            expected,
            &[
                IdentityPreparation::WriteCookie,
                IdentityPreparation::ReadCookie,
                IdentityPreparation::WriteOwner,
                IdentityPreparation::ReadOwner,
                IdentityPreparation::WriteRoot,
                IdentityPreparation::ReadRoot,
                IdentityPreparation::SeedRoot,
                IdentityPreparation::ReadSeed,
                IdentityPreparation::Freeze("TASK_COOKIE"),
                IdentityPreparation::Freeze("THREAD_OWNER"),
                IdentityPreparation::Freeze("ROOT_AFFILIATION"),
                IdentityPreparation::Freeze("COOKIE_CTL"),
                IdentityPreparation::Freeze("OWNER_CTL"),
                IdentityPreparation::Freeze("ROOT_CTL")
            ]
        );
        for fail in 0..expected.len() {
            let mut calls = Vec::new();
            let mut linked = false;
            let result = prepare_identity_with(true, |step| {
                calls.push(step);
                if calls.len() == fail + 1 {
                    bail!("injected setup failure");
                }
                Ok(())
            })
            .map(|()| {
                linked = true;
            });
            assert!(result.is_err());
            assert!(!linked);
            assert_eq!(calls, expected[..=fail]);
        }

        let mut unowned = Vec::new();
        prepare_identity_with(false, |step| {
            unowned.push(step);
            Ok(())
        })
        .unwrap();
        assert!(!unowned.contains(&IdentityPreparation::SeedRoot));
        assert!(!unowned.contains(&IdentityPreparation::ReadSeed));
        assert!(
            unowned
                .iter()
                .position(|step| *step == IdentityPreparation::ReadRoot)
                .unwrap()
                < unowned
                    .iter()
                    .position(|step| *step == IdentityPreparation::Freeze("ROOT_CTL"))
                    .unwrap()
        );
        for fail in 0..unowned.len() {
            let mut calls = Vec::new();
            let mut completed = false;
            let result = prepare_identity_with(false, |step| {
                calls.push(step);
                if calls.len() == fail + 1 {
                    bail!("injected unowned setup failure");
                }
                Ok(())
            })
            .map(|()| {
                completed = true;
            });
            assert!(result.is_err());
            assert!(!completed);
            assert!(!calls.contains(&IdentityPreparation::SeedRoot));
            assert!(!calls.contains(&IdentityPreparation::ReadSeed));
            assert_eq!(calls, unowned[..=fail]);
        }
    }

    #[test]
    fn identity_controls_read_back_every_named_field() {
        assert_eq!(
            cookie_control_fields(ImageIdentityControl {
                limit: 1,
                next_ticket: 2,
                unavailable: 3,
                create_failures: 4,
                retry_exhausted: 5
            }),
            [1, 2, 3, 4, 5]
        );
        assert_eq!(
            owner_control_fields(ThreadOwnerControl {
                limit: 1,
                outstanding: 2,
                poison: 3,
                admission_failures: 4,
                reclamation_failures: 5,
                abandoned_start: 6,
                abandoned_discovery: 7
            }),
            [1, 2, 3, 4, 5, 6, 7]
        );
        assert_eq!(
            root_control_fields(RootAffiliationControl {
                affiliation_reserved: 1,
                failure_flags: 2,
                admission_failures: 3,
                create_failures: 4,
                malformed_failures: 5,
                classifier_failures: 6,
                delete_failures: 7,
                refund_failures: 8,
            }),
            [1, 2, 3, 4, 5, 6, 7, 8]
        );
    }

    #[test]
    fn root_control_validator_rejects_each_individual_field_mismatch() {
        let expected = initial_root_control(true);
        validate_root_control_readback(expected, expected).unwrap();
        for actual in [
            RootAffiliationControl {
                affiliation_reserved: 0,
                ..expected
            },
            RootAffiliationControl {
                failure_flags: 1,
                ..expected
            },
            RootAffiliationControl {
                admission_failures: 1,
                ..expected
            },
            RootAffiliationControl {
                create_failures: 1,
                ..expected
            },
            RootAffiliationControl {
                malformed_failures: 1,
                ..expected
            },
            RootAffiliationControl {
                classifier_failures: 1,
                ..expected
            },
            RootAffiliationControl {
                delete_failures: 1,
                ..expected
            },
            RootAffiliationControl {
                refund_failures: 1,
                ..expected
            },
        ] {
            assert!(validate_root_control_readback(expected, actual).is_err());
        }
    }

    #[test]
    fn root_seed_uses_exact_original_pidfd_abi_and_same_fd_readback() {
        use std::os::fd::{AsFd as _, AsRawFd as _};
        use std::process::{Command, Stdio};

        const FD0_CHILD: &str = "P11SCOPE_ROOT_SEED_FD0_CHILD";
        if std::env::var_os(FD0_CHILD).is_none() {
            let status = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("attach::tests::root_seed_uses_exact_original_pidfd_abi_and_same_fd_readback")
                .arg("--nocapture")
                .env(FD0_CHILD, "1")
                .stdin(Stdio::from(std::fs::File::open("/dev/null").unwrap()))
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        let map = tempfile::tempfile().unwrap();
        let stdin = std::io::stdin();
        assert_eq!(stdin.as_fd().as_raw_fd(), 0);
        let map_fd = map.as_fd();
        let pidfd = stdin.as_fd();
        let expected_map_fd = map_fd.as_raw_fd() as u32;
        let mut calls = Vec::new();
        root_affiliation_element_with(
            map_fd,
            pidfd,
            RootElementOperation::Seed,
            |command, attr, size| {
                assert_eq!(size, std::mem::size_of::<BpfMapElementAttr>());
                assert_eq!(attr.map_fd, expected_map_fd);
                // SAFETY: the production seam keeps exact typed storage live for the call.
                calls.push((
                    command,
                    unsafe { *(attr.key as *const i32) },
                    unsafe { *(attr.value as *const u64) },
                    attr.flags,
                ));
                Ok(())
            },
        )
        .unwrap();
        root_affiliation_element_with(
            map_fd,
            pidfd,
            RootElementOperation::Read,
            |command, attr, size| {
                assert_eq!(size, std::mem::size_of::<BpfMapElementAttr>());
                assert_eq!(attr.map_fd, expected_map_fd);
                // SAFETY: simulate the kernel's exact positive u64 readback.
                unsafe { *(attr.value as *mut u64) = 1 };
                calls.push((
                    command,
                    unsafe { *(attr.key as *const i32) },
                    unsafe { *(attr.value as *const u64) },
                    attr.flags,
                ));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(calls, [(2, 0, 1, BPF_NOEXIST), (1, 0, 1, 0)]);
    }

    #[test]
    fn root_seed_refuses_duplicate_absence_errors_and_nonpositive_readback() {
        use std::os::fd::AsFd as _;
        let map = tempfile::tempfile().unwrap();
        let process = tempfile::tempfile().unwrap();
        let map_fd = map.as_fd();
        let pidfd = process.as_fd();
        for (operation, errno) in [
            (RootElementOperation::Seed, libc::EEXIST),
            (RootElementOperation::Read, libc::ENOENT),
            (RootElementOperation::Read, libc::EPERM),
        ] {
            let error = root_affiliation_element_with(map_fd, pidfd, operation, |_, _, _| {
                Err(std::io::Error::from_raw_os_error(errno))
            })
            .unwrap_err();
            assert_eq!(
                error
                    .root_cause()
                    .downcast_ref::<std::io::Error>()
                    .and_then(std::io::Error::raw_os_error),
                Some(errno)
            );
        }
        root_affiliation_element_with(map_fd, pidfd, RootElementOperation::Read, |_, attr, _| {
            // SAFETY: the production read seam supplies a live writable u64.
            unsafe { *(attr.value as *mut u64) = ROOT_AFFILIATION_POSITIVE };
            Ok(())
        })
        .unwrap();
        for invalid in [0, 2, u64::MAX] {
            let error = root_affiliation_element_with(
                map_fd,
                pidfd,
                RootElementOperation::Read,
                |_, attr, _| {
                    // SAFETY: the production read seam supplies a live writable u64.
                    unsafe { *(attr.value as *mut u64) = invalid };
                    Ok(())
                },
            )
            .unwrap_err();
            assert!(format!("{error:#}").contains("expected positive value 1"));
        }
    }

    #[test]
    fn root_seed_authority_requires_exact_pid_scope_and_original_descriptor() {
        use std::os::fd::{AsFd as _, AsRawFd as _};
        let missing = root_seed_authority(
            &Scope::Pid(17),
            17,
            Err(std::io::Error::other("process pin has no original pidfd")),
        )
        .unwrap_err();
        assert!(format!("{missing:#}").contains("no original pidfd"));
        let process = tempfile::tempfile().unwrap();
        let pidfd = process.as_fd();
        assert_eq!(
            root_seed_authority(&Scope::Pid(17), 17, Ok(pidfd))
                .unwrap()
                .as_raw_fd(),
            process.as_raw_fd()
        );
        assert!(root_seed_authority(&Scope::Pid(18), 17, Ok(pidfd)).is_err());
        let directory = tempfile::tempdir().unwrap();
        let dir = std::sync::Arc::new(std::fs::File::open(directory.path()).unwrap());
        assert!(
            root_seed_authority(
                &Scope::Cgroup {
                    id: 1,
                    path: directory.path().to_path_buf(),
                    dir
                },
                17,
                Ok(pidfd)
            )
            .is_err()
        );
    }

    #[test]
    fn root_control_is_zero_unowned_and_charged_once_owned() {
        assert_eq!(root_control_fields(initial_root_control(false)), [0; 8]);
        assert_eq!(
            root_control_fields(initial_root_control(true)),
            [1, 0, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn required_hooks_rollback_all_prior_links_and_retain_source() {
        let hooks = ["sched_process_exec", "sched_process_exit", "task_newtask"];
        for fail in 0..3 {
            let mut operations = Vec::new();
            let error = attach_lifecycle_with(
                &mut operations,
                |operations, name| {
                    operations.push(format!("attach {name}"));
                    if name == hooks[fail] {
                        return Err(std::io::Error::from_raw_os_error(libc::EPERM).into());
                    }
                    Ok(name)
                },
                |operations, name, _| {
                    operations.push(format!("detach {name}"));
                    bail!("rollback {name} failed")
                },
            )
            .unwrap_err();
            assert!(error.downcast_ref::<std::io::Error>().is_some());
            let mut expected: Vec<_> = hooks[..=fail]
                .iter()
                .map(|name| format!("attach {name}"))
                .collect();
            expected.extend(
                hooks[..fail]
                    .iter()
                    .rev()
                    .map(|name| format!("detach {name}")),
            );
            assert_eq!(operations, expected);
            let rendered = format!("{error:#}");
            assert!(rendered.contains(hooks[fail]));
            for name in &hooks[..fail] {
                assert!(rendered.contains(&format!("rollback {name} failed")));
            }
        }
        let mut calls = Vec::new();
        let links = attach_lifecycle_with(
            &mut calls,
            |calls, name| {
                calls.push(name);
                Ok(name)
            },
            |_, _, _| Ok(()),
        )
        .unwrap();
        assert_eq!(links, hooks);
        assert_eq!(calls, hooks);
    }

    #[test]
    fn cleanup_hooks_detach_after_shuffled_static_dynamic_and_diagnostic_links() {
        let mut detached = Vec::new();
        let failures = detach_selected_with(
            vec![
                (ProducerProgram::RawTracePoint("sched_process_exit"), "exit"),
                (
                    ProducerProgram::UProbe("function_list_return"),
                    "dynamic return",
                ),
                (ProducerProgram::UProbe("p11_entry"), "diagnostic"),
                (ProducerProgram::RawTracePoint("sched_process_exec"), "exec"),
                (ProducerProgram::UProbe("p11_return"), "static return"),
                (ProducerProgram::BtfTracePoint("task_newtask"), "typed"),
                (
                    ProducerProgram::UProbe("function_list_entry"),
                    "dynamic entry",
                ),
                (ProducerProgram::UProbe("p11_entry"), "static entry"),
            ],
            |link| {
                detached.push(link);
                bail!("detach {link}")
            },
        );
        assert_eq!(failures.len(), 8);
        assert_eq!(&detached[6..], &["exit", "exec"]);
    }

    #[test]
    fn failed_then_empty_detach_stays_uncertain_and_refuses_new_links() {
        let failures = vec!["detach failed".into()];
        let mut detached = false;
        assert!(
            finish_producer_detach(&mut detached, &failures, Err(anyhow!("detach failed")))
                .is_err()
        );
        assert!(!detached);
        assert!(finish_producer_detach(&mut detached, &failures, Ok(())).is_err());
        assert!(!detached);
        assert_eq!(
            events::poll_quantum(detached),
            Some(events::LIVE_POLL_QUANTUM)
        );
        let mut clean = false;
        finish_producer_detach(&mut clean, &[], Ok(())).unwrap();
        assert_eq!(
            events::poll_quantum(clean),
            Some(events::TERMINAL_DRAIN_BOUND)
        );
        assert!(attachment_admission(&failures, true).is_err());
        attachment_admission(&failures, false).unwrap();
    }

    #[test]
    fn unsupported_environment_hint_preserves_the_underlying_error_chain() {
        #[derive(Debug)]
        struct Injected;
        impl std::fmt::Display for Injected {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("injected loader failure")
            }
        }
        impl std::error::Error for Injected {}

        let error = unsupported_environment_context(
            anyhow::Error::new(Injected).context("loading required typed task_newtask"),
        );
        assert!(error.downcast_ref::<Injected>().is_some());
        let rendered = format!("{error:#}");
        assert!(rendered.contains("loading required typed task_newtask"));
        assert!(rendered.contains("injected loader failure"));
        assert!(rendered.contains(UNSUPPORTED_ENV_HINT));
    }
    use super::*;

    fn expected_preparation(unsafe_object: bool) -> Vec<SessionPreparation> {
        use SessionPreparation::*;
        let mut steps = vec![
            ValidatePolicy,
            ValidateRuntime,
            ValidateStopGate,
            ValidatePrograms,
            PublishScope,
            PrepareIdentity,
            PublishDescriptors,
            PublishAsync,
            PublishShapes,
            PublishAttributes,
            FreezePublished,
            SelectScope,
            LoadProgram("dl_debug_state"),
            LoadProgram("function_list_entry"),
            LoadProgram("function_list_return"),
            LoadProgram("interface_entry"),
            LoadProgram("interface_list_entry"),
            LoadProgram("interface_list_return"),
            LoadProgram("interface_list_worker"),
            LoadProgram("interface_return"),
            LoadProgram("p11_entry"),
        ];
        if unsafe_object {
            steps.extend([
                LoadProgram("p11_entry_ia32"),
                LoadProgram("p11_entry_template"),
                LoadProgram("p11_entry_template_pair"),
                LoadProgram("p11_entry_template_second"),
                LoadProgram("p11_entry_template_types"),
            ]);
        }
        steps.extend([
            LoadProgram("p11_return"),
            LoadProgram("sched_process_exec"),
            LoadProgram("sched_process_exit"),
            LoadProgram("task_newtask"),
            LoadImagePrograms,
            FreezeDeferred("CONFIG"),
            FreezeDeferred("DESCRIPTORS"),
            PublishTailCalls,
            PrepareEventsDomain,
        ]);
        steps
    }

    #[test]
    fn image_program_load_precedes_deferred_freeze_and_lifecycle_activation() {
        for unsafe_object in [false, true] {
            let image_loaded = std::cell::Cell::new(false);
            let deferred_frozen = std::cell::Cell::new(0);
            let activation_called = std::cell::Cell::new(false);
            let preparation = prepare_session_with(unsafe_object, |step| {
                if step == SessionPreparation::LoadImagePrograms {
                    assert_eq!(deferred_frozen.get(), 0);
                    image_loaded.set(true);
                }
                if let SessionPreparation::FreezeDeferred(_) = step {
                    anyhow::ensure!(
                        image_loaded.get(),
                        "native query/hooks must load before deferred policy freeze"
                    );
                    deferred_frozen.set(deferred_frozen.get() + 1);
                }
                Ok(())
            });
            activate_after_preparation_with(preparation, || {
                assert!(image_loaded.get());
                assert_eq!(deferred_frozen.get(), 2);
                activation_called.set(true);
                Ok(())
            })
            .unwrap();
            assert!(activation_called.get());
        }
    }

    #[test]
    fn preparation_contract_runs_every_phase_successfully() {
        for unsafe_object in [false, true] {
            let mut seen = Vec::new();
            prepare_session_with(unsafe_object, |step| {
                seen.push(step);
                Ok(())
            })
            .unwrap();
            assert_eq!(seen, expected_preparation(unsafe_object));
        }
    }

    #[test]
    fn successful_preparation_reaches_actual_lifecycle_activation() {
        for unsafe_object in [false, true] {
            let expected = expected_preparation(unsafe_object);
            let mut preparation = Vec::new();
            let mut activation_calls = 0;
            let mut attach_calls = Vec::new();
            let preparation_result = prepare_session_with(unsafe_object, |step| {
                preparation.push(step);
                Ok(())
            });
            let (events_domain, links) =
                activate_after_preparation_with(preparation_result, || {
                    assert_eq!(preparation, expected);
                    activation_calls += 1;
                    let links = attach_lifecycle_with(
                        &mut attach_calls,
                        |calls, program| {
                            calls.push(program);
                            Ok(program)
                        },
                        |_, _, _| Ok(()),
                    )?;
                    Ok(("events-domain", links))
                })
                .unwrap();

            assert_eq!(events_domain, "events-domain");
            assert_eq!(activation_calls, 1);
            assert_eq!(
                attach_calls,
                ["sched_process_exec", "sched_process_exit", "task_newtask"]
            );
            assert_eq!(
                links,
                ["sched_process_exec", "sched_process_exit", "task_newtask"]
            );
        }
    }

    #[test]
    fn preparation_contract_preserves_each_error_and_stops_later_operations() {
        #[derive(Debug)]
        struct Injected(usize);
        impl std::fmt::Display for Injected {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "injected phase {}", self.0)
            }
        }
        impl std::error::Error for Injected {}
        for unsafe_object in [false, true] {
            let expected = expected_preparation(unsafe_object);
            for fail in 0..expected.len() {
                let mut seen = Vec::new();
                let mut activation_calls = 0;
                let mut attach_calls = 0;
                let preparation_result = prepare_session_with(unsafe_object, |step| {
                    seen.push(step);
                    if seen.len() == fail + 1 {
                        return Err(Injected(fail).into());
                    }
                    Ok(())
                });
                let error = activate_after_preparation_with(preparation_result, || {
                    activation_calls += 1;
                    attach_lifecycle_with(
                        &mut attach_calls,
                        |calls, _| {
                            *calls += 1;
                            Ok(())
                        },
                        |_, _, _| Ok(()),
                    )
                })
                .unwrap_err();
                assert_eq!(seen, expected[..=fail]);
                assert_eq!(activation_calls, 0);
                assert_eq!(attach_calls, 0);
                assert_eq!(error.downcast_ref::<Injected>().unwrap().0, fail);
                assert_eq!(error.to_string(), format!("injected phase {fail}"));
            }
        }
    }

    #[test]
    fn successful_preparation_preserves_typed_activation_failure() {
        #[derive(Debug)]
        struct ActivationFailure;
        impl std::fmt::Display for ActivationFailure {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("typed activation failure")
            }
        }
        impl std::error::Error for ActivationFailure {}

        for unsafe_object in [false, true] {
            let mut activation_calls = 0;
            let preparation = prepare_session_with(unsafe_object, |_| Ok(()));
            let result: Result<()> = activate_after_preparation_with(preparation, || {
                activation_calls += 1;
                Err(ActivationFailure.into())
            });
            let error = result.unwrap_err();
            assert_eq!(activation_calls, 1);
            assert!(error.downcast_ref::<ActivationFailure>().is_some());
            assert_eq!(error.to_string(), "typed activation failure");
        }
    }

    #[derive(Debug, PartialEq, Eq)]
    enum TailOperation {
        Write(u32),
        Read(u32),
        Freeze,
    }

    #[test]
    fn tail_contract_writes_reads_exact_ids_then_freezes() {
        let mut seen = Vec::new();
        publish_tail_calls_with(
            &mut seen,
            701,
            |seen, slot| {
                seen.push(TailOperation::Write(slot));
                Ok(())
            },
            |seen, slot| {
                seen.push(TailOperation::Read(slot));
                Ok(if slot == 0 { Some(701) } else { None })
            },
            |seen| {
                seen.push(TailOperation::Freeze);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            seen,
            vec![
                TailOperation::Write(0),
                TailOperation::Read(0),
                TailOperation::Read(1),
                TailOperation::Freeze,
            ]
        );
    }

    #[test]
    fn pair_contract_writes_reads_exact_id_then_freezes() {
        let mut seen = Vec::new();
        publish_pair_calls_with(
            &mut seen,
            902,
            |seen, slot| {
                seen.push(TailOperation::Write(slot));
                Ok(())
            },
            |seen, slot| {
                seen.push(TailOperation::Read(slot));
                assert_eq!(slot, 0);
                Ok(Some(902))
            },
            |seen| {
                seen.push(TailOperation::Freeze);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            seen,
            vec![
                TailOperation::Write(0),
                TailOperation::Read(0),
                TailOperation::Freeze,
            ]
        );
    }

    #[test]
    fn tail_contract_rejects_absence_wrong_ids_and_occupied_retired_slot_before_freeze() {
        for (worker_read, retired_read, message, reads) in [
            (None, None, "worker", vec![0]),
            (Some(700), None, "worker", vec![0]),
            (Some(701), Some(902), "retired", vec![0, 1]),
        ] {
            let mut seen = Vec::new();
            let error = publish_tail_calls_with(
                &mut seen,
                701,
                |_, _| Ok(()),
                |seen, slot| {
                    seen.push(slot);
                    Ok(if slot == 0 { worker_read } else { retired_read })
                },
                |_| panic!("inexact readback must not freeze"),
            )
            .unwrap_err();
            assert!(error.to_string().contains(message), "{error}");
            assert_eq!(seen, reads);
        }
    }

    #[test]
    fn pair_contract_rejects_absence_and_wrong_id_before_freeze() {
        for (second_read, reads) in [(None, vec![0]), (Some(903), vec![0])] {
            let mut seen = Vec::new();
            let error = publish_pair_calls_with(
                &mut seen,
                902,
                |_, _| Ok(()),
                |seen, slot| {
                    seen.push(slot);
                    Ok(second_read)
                },
                |_| panic!("inexact readback must not freeze"),
            )
            .unwrap_err();
            assert!(error.to_string().contains("template-second"), "{error}");
            assert_eq!(seen, reads);
        }
    }

    #[test]
    fn tail_contract_distinguishes_empty_retired_slot_from_lookup_failure() {
        for errno in [libc::ENOENT, libc::EPERM, libc::EIO] {
            let mut frozen = false;
            let result = publish_tail_calls_with(
                &mut frozen,
                701,
                |_, _| Ok(()),
                |_, slot| {
                    program_array_lookup_result(
                        "TAIL_CALLS",
                        slot,
                        701,
                        if slot == 0 {
                            Ok(())
                        } else {
                            Err(io::Error::from_raw_os_error(errno))
                        },
                    )
                },
                |frozen| {
                    *frozen = true;
                    Ok(())
                },
            );
            if errno == libc::ENOENT {
                result.unwrap();
                assert!(frozen);
            } else {
                let error = result.unwrap_err();
                assert_eq!(
                    error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
                    Some(errno)
                );
                assert_eq!(error.to_string(), "reading back TAIL_CALLS[1]");
                assert!(!frozen);
            }
        }
    }

    #[test]
    fn pair_contract_distinguishes_missing_slot_from_lookup_failure() {
        for errno in [libc::ENOENT, libc::EPERM, libc::EIO] {
            let mut frozen = false;
            let result = publish_pair_calls_with(
                &mut frozen,
                902,
                |_, _| Ok(()),
                |_, slot| {
                    program_array_lookup_result(
                        "PAIR_CALLS",
                        slot,
                        902,
                        Err(io::Error::from_raw_os_error(errno)),
                    )
                },
                |frozen| {
                    *frozen = true;
                    Ok(())
                },
            );
            let error = result.unwrap_err();
            assert!(!frozen);
            if errno == libc::ENOENT {
                assert!(error.to_string().contains("template-second"), "{error}");
            } else {
                assert_eq!(
                    error.downcast_ref::<io::Error>().unwrap().raw_os_error(),
                    Some(errno)
                );
                assert_eq!(error.to_string(), "reading back PAIR_CALLS[0]");
            }
        }
    }

    #[test]
    fn tail_contract_preserves_every_io_failure_and_stops() {
        let expected = [
            TailOperation::Write(0),
            TailOperation::Read(0),
            TailOperation::Read(1),
            TailOperation::Freeze,
        ];
        for fail in 0..expected.len() {
            let mut seen = Vec::new();
            let record = |seen: &mut Vec<TailOperation>, op| -> Result<()> {
                seen.push(op);
                if seen.len() == fail + 1 {
                    bail!("injected tail I/O failure {fail}");
                }
                Ok(())
            };
            let error = publish_tail_calls_with(
                &mut seen,
                701,
                |seen, slot| record(seen, TailOperation::Write(slot)),
                |seen, slot| {
                    record(seen, TailOperation::Read(slot))?;
                    Ok(if slot == 0 { Some(701) } else { None })
                },
                |seen| record(seen, TailOperation::Freeze),
            )
            .unwrap_err();
            assert_eq!(seen, expected[..=fail]);
            assert_eq!(
                error.to_string(),
                format!("injected tail I/O failure {fail}")
            );
        }
    }

    #[test]
    fn pair_contract_preserves_every_io_failure_and_stops() {
        let expected = [
            TailOperation::Write(0),
            TailOperation::Read(0),
            TailOperation::Freeze,
        ];
        for fail in 0..expected.len() {
            let mut seen = Vec::new();
            let record = |seen: &mut Vec<TailOperation>, op| -> Result<()> {
                seen.push(op);
                if seen.len() == fail + 1 {
                    bail!("injected pair I/O failure {fail}");
                }
                Ok(())
            };
            let error = publish_pair_calls_with(
                &mut seen,
                902,
                |seen, slot| record(seen, TailOperation::Write(slot)),
                |seen, slot| {
                    record(seen, TailOperation::Read(slot))?;
                    Ok(Some(902))
                },
                |seen| record(seen, TailOperation::Freeze),
            )
            .unwrap_err();
            assert_eq!(seen, expected[..=fail]);
            assert_eq!(
                error.to_string(),
                format!("injected pair I/O failure {fail}")
            );
        }
    }

    #[test]
    fn aya_cookie_contract_preserves_both_words_through_return_first_scheduling() {
        let mut first = test_slot(0x1020_3040);
        first.descriptor_index = 0x5060_7080;
        first.file_offset = 0x1234_5678_9abc;
        let mut second = test_slot(0xa1b2_c3d4);
        second.descriptor_index = 0xe5f6_0718;
        second.file_offset = 0x9876_5432_1000;
        for fail_return in [false, true] {
            let mut seen = Vec::new();
            let outcome = attach_targets_with(
                &[first.clone(), second.clone()],
                CapturePolicy::Allowlisted,
                false,
                |_| Ok(ElfAbi::Lp64),
                |program, slot, point| {
                    let UProbeAttachLocation::AbsoluteOffset(offset) = point.location else {
                        panic!("slot attaches must retain the concrete file offset");
                    };
                    seen.push((program, slot.index, offset, point.cookie));
                    if fail_return && program == "p11_return" && slot.index == 0x1020_3040 {
                        bail!("return refused");
                    }
                    Ok(())
                },
                |_| Some(10),
            )
            .unwrap();
            let mut expected = vec![
                (
                    "p11_return",
                    0x1020_3040,
                    0x1234_5678_9abc,
                    Some(0x5060_7080_1020_3040),
                ),
                (
                    "p11_return",
                    0xa1b2_c3d4,
                    0x9876_5432_1000,
                    Some(0xe5f6_0718_a1b2_c3d4),
                ),
            ];
            if !fail_return {
                expected.push((
                    "p11_entry",
                    0x1020_3040,
                    0x1234_5678_9abc,
                    Some(0x5060_7080_1020_3040),
                ));
            }
            expected.push((
                "p11_entry",
                0xa1b2_c3d4,
                0x9876_5432_1000,
                Some(0xe5f6_0718_a1b2_c3d4),
            ));
            assert_eq!(seen, expected);
            assert_eq!(outcome.failures.len(), usize::from(fail_return));
        }
    }

    #[derive(Default)]
    struct DescriptorPublicationIo {
        writes: Vec<(u32, SlotSemantics)>,
        read_calls: usize,
    }

    #[test]
    fn descriptor_publication_writes_the_full_fixed_inventory_then_reads_it_once() {
        let mut io = DescriptorPublicationIo::default();

        publish_descriptors(
            &mut io,
            |io, index, value| {
                io.writes.push((index, value));
                Ok(())
            },
            |io| {
                io.read_calls += 1;
                Ok(io.writes.iter().map(|(_, value)| *value).collect())
            },
        )
        .unwrap();

        assert_eq!(io.writes.len(), 105);
        assert_eq!(io.read_calls, 1);
        assert_eq!(
            io.writes,
            crate::kinds::DESCRIPTORS
                .iter()
                .copied()
                .enumerate()
                .map(|(index, value)| (index as u32, value))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn descriptor_publication_stops_at_each_injected_write_failure() {
        for failed_index in [0, 52, 104] {
            let mut io = DescriptorPublicationIo::default();

            let error = publish_descriptors(
                &mut io,
                |io, index, value| {
                    io.writes.push((index, value));
                    if index == failed_index {
                        anyhow::bail!("injected descriptor write failure at {index}");
                    }
                    Ok(())
                },
                |io| {
                    io.read_calls += 1;
                    Ok(Vec::new())
                },
            )
            .unwrap_err();

            assert_eq!(
                error.to_string(),
                format!("injected descriptor write failure at {failed_index}")
            );
            assert_eq!(
                io.writes
                    .iter()
                    .map(|(index, _)| *index)
                    .collect::<Vec<_>>(),
                (0..=failed_index).collect::<Vec<_>>()
            );
            assert_eq!(io.read_calls, 0);
        }
    }

    #[test]
    fn descriptor_publication_preserves_read_failure() {
        let mut io = DescriptorPublicationIo::default();

        let error = publish_descriptors(
            &mut io,
            |io, index, value| {
                io.writes.push((index, value));
                Ok(())
            },
            |io| {
                io.read_calls += 1;
                anyhow::bail!("injected descriptor read failure")
            },
        )
        .unwrap_err();

        assert_eq!(error.to_string(), "injected descriptor read failure");
        assert_eq!(io.writes.len(), 105);
        assert_eq!(io.read_calls, 1);
    }

    #[test]
    fn descriptor_publication_rejects_every_inexact_readback_shape() {
        let expected = crate::kinds::DESCRIPTORS.to_vec();
        let mut missing = expected.clone();
        missing.pop();
        let mut extra = expected.clone();
        extra.push(SlotSemantics::COUNT_ONLY);
        let mut different = expected.clone();
        different[52].operations ^= 1;

        for actual in [missing, extra, different] {
            let mut io = DescriptorPublicationIo::default();
            let error = publish_descriptors(
                &mut io,
                |io, index, value| {
                    io.writes.push((index, value));
                    Ok(())
                },
                |io| {
                    io.read_calls += 1;
                    Ok(actual)
                },
            )
            .unwrap_err();

            assert_eq!(
                error.to_string(),
                "DESCRIPTORS exact readback differs from the fixed inventory"
            );
            assert_eq!(io.writes.len(), 105);
            assert_eq!(io.read_calls, 1);
        }
    }

    #[test]
    fn rdonly_arrays_with_many_entries_freeze_only_after_programs_load() {
        // A frozen BPF_F_RDONLY_PROG array makes the verifier constant-fold
        // constant-offset reads of it, and the kernel's
        // `array_map_direct_value_addr()` refuses any array with
        // `max_entries != 1` with its internal ENOTSUPP. That reaches userspace
        // as a bare `os error 524` from BPF_PROG_LOAD with no rejection
        // message, and it is invisible on kernels new enough to have dropped
        // the restriction, so no dev-machine gate catches it. W3's `02eedbd`
        // took CONFIG from 1 to 2 entries and broke every kernel below ~7.0.
        for (name, meta) in BASE_POLICY_MAPS {
            let trips_the_kernel = matches!(meta.map_type, MapType::Array)
                && meta.flags & BPF_F_RDONLY_PROG != 0
                && meta.max_entries != 1;
            assert!(
                !trips_the_kernel || defers_freeze_until_loaded(name, &meta),
                "{name} is a frozen read-only array with {} entries, so freezing it \
                 before the programs load makes BPF_PROG_LOAD fail with ENOTSUPP",
                meta.max_entries
            );
        }
        // Pinned, not derived: bumping a max_entries from 1, or adding a
        // read-only array, silently moves a map across this boundary. Making
        // that edit fail here forces it to be a deliberate one.
        let deferred: Vec<&str> = BASE_POLICY_MAPS
            .iter()
            .filter(|(name, meta)| defers_freeze_until_loaded(name, meta))
            .map(|(name, _)| *name)
            .collect();
        assert_eq!(deferred, ["CONFIG", "DESCRIPTORS", TAIL_POLICY_MAP]);
        // PAIR_CALLS is the only feature map populated after the load, so it
        // is the only one that defers its freeze past publication.
        let deferred_feature: Vec<&str> = FEATURE_POLICY_MAPS
            .iter()
            .filter(|(name, meta)| defers_freeze_until_loaded(name, meta))
            .map(|(name, _)| *name)
            .collect();
        assert_eq!(deferred_feature, [PAIR_POLICY_MAP]);
    }

    #[test]
    fn dynamic_export_sequence_retains_partial_success_and_cleans_up_once() {
        let mut failed = DynamicAttachEvidence::default();
        let mut state = Vec::new();
        assert_eq!(
            attach_dynamic_export_with(
                &mut state,
                &mut failed,
                |state, is_return| {
                    state.push(if is_return { "return" } else { "entry" });
                    Err::<u8, _>("return failed")
                },
                |state, _| state.push("cleanup"),
            ),
            Err("return failed")
        );
        assert!(!failed.successful());
        assert_eq!(state, ["return"]);

        let mut evidence = DynamicAttachEvidence::default();
        state.clear();
        assert_eq!(
            attach_dynamic_export_with(
                &mut state,
                &mut evidence,
                |state, is_return| {
                    state.push(if is_return { "return" } else { "entry" });
                    if is_return {
                        Ok(1)
                    } else {
                        Err("entry failed")
                    }
                },
                |state, _| state.push("cleanup"),
            ),
            Err("entry failed")
        );
        assert_eq!(state, ["return", "entry", "cleanup"]);
        assert!(evidence.successful());
    }

    #[test]
    fn individual_dynamic_attach_records_lifetime_success() {
        let mut evidence = DynamicAttachEvidence::default();
        let mut state = ();
        assert_eq!(
            record_dynamic_attach_with(&mut state, &mut evidence, |_| Ok::<_, &str>(2)),
            Ok(2)
        );
        assert!(evidence.successful());
    }
    use p11scope_ebpf_common::{ARG_NONE, SlotSemantics};
    use std::io;

    fn test_slot(index: u32) -> crate::plan::Slot {
        crate::plan::Slot {
            index,
            descriptor_index: 0,
            object: crate::plan::TEST_PINNED_OBJECT,
            object_path: "/proc/self/fd/42".into(),
            file_offset: 0x10 + u64::from(index) * 8,
            names: vec!["C_Sign".into()],
            aliased: false,
            semantics: SlotSemantics::COUNT_ONLY,
            semantic_authorized: false,
            semantic_ambiguous: false,
            fork_safe: false,
            module_ids: vec![crate::plan::ModuleId(0)],
        }
    }

    fn group_slot(index: u32, object: u32, semantics: SlotSemantics) -> crate::plan::Slot {
        let mut slot = test_slot(index);
        slot.object = PinnedObjectId(object);
        slot.semantics = semantics;
        slot
    }

    fn group_targets(entries: &[(u32, &str, ElfAbi)]) -> BTreeMap<u32, (PathBuf, ElfAbi)> {
        entries
            .iter()
            .map(|(index, path, abi)| (*index, (PathBuf::from(path), *abi)))
            .collect()
    }

    fn group_member_indices(group: &StaticGroup) -> Vec<u32> {
        group.members.iter().map(|m| m.slot.index).collect()
    }

    fn grouped_offset(groups: &[StaticGroup], index: u32) -> u64 {
        groups
            .iter()
            .flat_map(|group| &group.members)
            .find(|member| member.slot.index == index)
            .unwrap_or_else(|| panic!("slot {index} is grouped"))
            .offset
    }

    #[test]
    fn groups_split_by_attach_path_and_entry_program() {
        let slots = vec![
            group_slot(0, 1, SlotSemantics::COUNT_ONLY),
            group_slot(1, 1, SlotSemantics::COUNT_ONLY),
            group_slot(2, 2, SlotSemantics::COUNT_ONLY),
            group_slot(3, 2, SlotSemantics::COUNT_ONLY),
        ];
        let targets = group_targets(&[
            (0, "/a.so", ElfAbi::Lp64),
            (1, "/a.so", ElfAbi::Lp64),
            (2, "/b.so", ElfAbi::Lp64),
            (3, "/b.so", ElfAbi::Ilp32),
        ]);
        let groups = group_static_slots(&slots, CapturePolicy::Allowlisted, true, &targets);
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].path, PathBuf::from("/a.so"));
        assert_eq!(groups[0].entry_program, "p11_entry");
        assert_eq!(group_member_indices(&groups[0]), vec![0, 1]);
        assert_eq!(groups[1].path, PathBuf::from("/b.so"));
        assert_eq!(groups[1].entry_program, "p11_entry");
        assert_eq!(group_member_indices(&groups[1]), vec![2]);
        assert_eq!(groups[2].path, PathBuf::from("/b.so"));
        assert_eq!(groups[2].entry_program, "p11_entry_ia32");
        assert_eq!(group_member_indices(&groups[2]), vec![3]);
        for group in &groups {
            for member in &group.members {
                assert_eq!(member.offset, member.slot.file_offset);
                assert_eq!(
                    member.cookie,
                    attach_cookie(member.slot.index, member.slot.descriptor_index)
                );
            }
        }
    }

    #[test]
    fn groups_sort_scrambled_members_deterministically() {
        let slots = vec![
            group_slot(3, 2, SlotSemantics::COUNT_ONLY),
            group_slot(0, 1, SlotSemantics::COUNT_ONLY),
            group_slot(2, 2, SlotSemantics::COUNT_ONLY),
            group_slot(1, 1, SlotSemantics::COUNT_ONLY),
        ];
        let targets = group_targets(&[
            (0, "/a.so", ElfAbi::Lp64),
            (1, "/a.so", ElfAbi::Lp64),
            (2, "/b.so", ElfAbi::Lp64),
            (3, "/b.so", ElfAbi::Lp64),
        ]);
        let groups = group_static_slots(&slots, CapturePolicy::Allowlisted, false, &targets);
        assert_eq!(groups.len(), 2);
        assert_eq!(group_member_indices(&groups[0]), vec![0, 1]);
        assert_eq!(group_member_indices(&groups[1]), vec![2, 3]);
    }

    type MockLink = Vec<(u64, u64)>;

    type MockCall = (String, bool, Vec<(u64, u64)>);
    type MockFail = dyn Fn(&str, &[(u64, u64)], bool) -> Option<io::Error>;

    struct MockGroup {
        calls: std::cell::RefCell<Vec<MockCall>>,
        fail: Box<MockFail>,
    }

    impl MockGroup {
        fn leaf(
            &self,
        ) -> impl FnMut(&'static str, &Path, &[(u64, u64)], bool) -> io::Result<MockLink> + '_
        {
            |program, path, sites, is_return| {
                self.calls
                    .borrow_mut()
                    .push((program.to_string(), is_return, sites.to_vec()));
                if let Some(error) = (self.fail)(path.to_str().unwrap(), sites, is_return) {
                    return Err(error);
                }
                Ok(sites.to_vec())
            }
        }

        fn programs_called(&self) -> Vec<(String, bool)> {
            self.calls
                .borrow()
                .iter()
                .map(|(program, is_return, _)| (program.clone(), *is_return))
                .collect()
        }
    }

    fn two_groups() -> (Vec<crate::plan::Slot>, BTreeMap<u32, (PathBuf, ElfAbi)>) {
        let slots = vec![
            group_slot(0, 1, SlotSemantics::COUNT_ONLY),
            group_slot(1, 1, SlotSemantics::COUNT_ONLY),
            group_slot(2, 2, SlotSemantics::COUNT_ONLY),
            group_slot(3, 2, SlotSemantics::COUNT_ONLY),
        ];
        let targets = group_targets(&[
            (0, "/a.so", ElfAbi::Lp64),
            (1, "/a.so", ElfAbi::Lp64),
            (2, "/b.so", ElfAbi::Lp64),
            (3, "/b.so", ElfAbi::Lp64),
        ]);
        (slots, targets)
    }

    #[test]
    fn multi_all_good_links_return_before_entry_per_group() {
        let (slots, targets) = two_groups();
        let groups = group_static_slots(&slots, CapturePolicy::Allowlisted, false, &targets);
        assert_eq!(groups.len(), 2);
        let mock = MockGroup {
            calls: std::cell::RefCell::new(Vec::new()),
            fail: Box::new(|_, _, _| None),
        };
        let (bundles, outcome) =
            attach_target_groups_with(&groups, |_| Some(7), mock.leaf()).unwrap();
        assert_eq!(bundles.len(), 4);
        for bundle in &bundles {
            assert_eq!(bundle.links.len(), 1);
            assert_eq!(bundle.slots.len(), 2);
        }
        assert_eq!(bundles[0].program, "p11_return");
        assert_eq!(bundles[1].program, "p11_entry");
        assert_eq!(bundles[2].program, "p11_return");
        assert_eq!(bundles[3].program, "p11_entry");
        assert_eq!(outcome.successful.len(), 8);
        assert!(outcome.failures.is_empty());
        assert!(!outcome.exhausted);
        assert_eq!(outcome.completed.len(), 4);
        assert!(
            outcome.completed.iter().all(|(_, at)| *at == Some(7)),
            "completed carries the clock"
        );
        assert_eq!(mock.calls.borrow().len(), 4);
        let called: Vec<(String, bool)> = mock.programs_called();
        let called: Vec<(&str, bool)> = called.iter().map(|(p, r)| (p.as_str(), *r)).collect();
        assert_eq!(
            called,
            vec![
                ("p11_return", true),
                ("p11_entry", false),
                ("p11_return", true),
                ("p11_entry", false),
            ]
        );
    }

    #[test]
    fn multi_poison_return_refusal_skips_entry_for_that_member() {
        let (slots, targets) = two_groups();
        let groups = group_static_slots(&slots, CapturePolicy::Allowlisted, false, &targets);
        let poison = grouped_offset(&groups, 1);
        let mock = MockGroup {
            calls: std::cell::RefCell::new(Vec::new()),
            fail: Box::new(move |_, sites, is_return| {
                if is_return && sites.iter().any(|(offset, _)| *offset == poison) {
                    Some(io::Error::from_raw_os_error(libc::EINVAL))
                } else {
                    None
                }
            }),
        };
        let (bundles, outcome) =
            attach_target_groups_with(&groups, |_| Some(7), mock.leaf()).unwrap();
        assert_eq!(outcome.successful.len(), 6);
        assert_eq!(outcome.failures.len(), 1);
        assert_eq!(outcome.failures[0].0, 1);
        assert!(
            outcome.failures[0]
                .1
                .starts_with("p11_return at /a.so+0x18: ")
        );
        assert_eq!(outcome.completed.len(), 3);
        // Entry never saw the refused member's offset.
        for (program, is_return, sites) in mock.calls.borrow().iter() {
            if program == "p11_entry" && !is_return {
                assert!(
                    sites.iter().all(|(offset, _)| *offset != poison),
                    "entry must exclude return-refused members"
                );
            }
        }
        let return_a = bundles.iter().find(|b| b.program == "p11_return").unwrap();
        assert_eq!(return_a.slots, vec![0]);
    }

    #[test]
    fn multi_entry_poison_leaves_return_and_records_entry_failure() {
        let (slots, targets) = two_groups();
        let groups = group_static_slots(&slots, CapturePolicy::Allowlisted, false, &targets);
        let poison = grouped_offset(&groups, 3);
        let mock = MockGroup {
            calls: std::cell::RefCell::new(Vec::new()),
            fail: Box::new(move |_, sites, is_return| {
                if !is_return && sites.iter().any(|(offset, _)| *offset == poison) {
                    Some(io::Error::from_raw_os_error(libc::EINVAL))
                } else {
                    None
                }
            }),
        };
        let (bundles, outcome) =
            attach_target_groups_with(&groups, |_| Some(7), mock.leaf()).unwrap();
        assert_eq!(outcome.successful.len(), 7);
        assert_eq!(outcome.failures.len(), 1);
        assert_eq!(outcome.failures[0].0, 3);
        assert!(
            outcome.failures[0]
                .1
                .starts_with("p11_entry at /b.so+0x28: ")
        );
        assert_eq!(outcome.completed.len(), 3);
        // The return endpoint stays successful without its entry.
        assert!(outcome.successful.contains(&(3, ProbeSide::Return)));
        assert!(!outcome.successful.contains(&(3, ProbeSide::Entry)));
        assert_eq!(bundles.len(), 4);
    }

    #[test]
    fn multi_permission_error_fails_the_side_and_continues() {
        let (slots, targets) = two_groups();
        let groups = group_static_slots(&slots, CapturePolicy::Allowlisted, false, &targets);
        let mock = MockGroup {
            calls: std::cell::RefCell::new(Vec::new()),
            fail: Box::new(|path, _, _| {
                if path == "/a.so" {
                    Some(io::Error::from_raw_os_error(libc::EPERM))
                } else {
                    None
                }
            }),
        };
        let (bundles, outcome) =
            attach_target_groups_with(&groups, |_| Some(7), mock.leaf()).unwrap();
        // Group /a.so refused wholesale (one fail-fast attempt, no entry
        // attempts); group /b.so attached fully.
        let calls = mock.calls.borrow();
        assert_eq!(calls.len(), 3);
        for (program, _, sites) in calls.iter() {
            if program == "p11_entry" {
                assert!(
                    sites.iter().all(|(offset, _)| *offset >= 0x20),
                    "no entry attempts for the refused group"
                );
            }
        }
        assert_eq!(outcome.successful.len(), 4);
        assert_eq!(outcome.failures.len(), 2);
        assert_eq!(bundles.len(), 2);
        assert!(bundles.iter().all(|b| b.slots == vec![2, 3]));
    }

    #[test]
    fn multi_exhaustion_ends_the_run_with_a_summary() {
        let (slots, targets) = two_groups();
        let groups = group_static_slots(&slots, CapturePolicy::Allowlisted, false, &targets);
        let mock = MockGroup {
            calls: std::cell::RefCell::new(Vec::new()),
            fail: Box::new(|_, _, is_return| {
                if !is_return {
                    Some(io::Error::from_raw_os_error(libc::EMFILE))
                } else {
                    None
                }
            }),
        };
        let (bundles, outcome) =
            attach_target_groups_with(&groups, |_| Some(7), mock.leaf()).unwrap();
        assert!(outcome.exhausted);
        // The summary first, then slot 1 (return-only) and the unattempted
        // group's slots 2 and 3, each failed explicitly.
        assert_eq!(
            outcome
                .failures
                .iter()
                .map(|(slot, _)| *slot)
                .collect::<Vec<_>>(),
            [0, 1, 2, 3]
        );
        assert_eq!(outcome.failures[0].0, 0);
        assert_eq!(
            outcome.failures[0].1,
            "fd table exhausted attaching slot 0 (2 endpoints across 1 links); \
             raise RLIMIT_NOFILE (ulimit -n) and retry"
        );
        // Partial links are kept; later groups are never attempted.
        assert_eq!(bundles.len(), 1);
        assert_eq!(bundles[0].program, "p11_return");
        assert!(
            mock.calls
                .borrow()
                .iter()
                .all(|(_, _, sites)| sites.len() <= 2)
        );
        assert_eq!(outcome.successful.len(), 2);
        assert!(outcome.completed.is_empty());
    }

    #[test]
    fn multi_exhaustion_fails_every_unfinished_member_explicitly() {
        for (failed_path, failed_return, expected_failures, expected_completed) in [
            ("/a.so", true, vec![0, 1, 2, 3], vec![]),
            ("/a.so", false, vec![0, 1, 2, 3], vec![]),
            ("/b.so", true, vec![2, 3], vec![0, 1]),
            ("/b.so", false, vec![2, 3], vec![0, 1]),
        ] {
            let case = format!("{failed_path} return={failed_return}");
            let (slots, targets) = two_groups();
            let groups = group_static_slots(&slots, CapturePolicy::Allowlisted, false, &targets);
            let mock = MockGroup {
                calls: std::cell::RefCell::new(Vec::new()),
                fail: Box::new(move |path, _, is_return| {
                    (path == failed_path && is_return == failed_return)
                        .then(|| io::Error::from_raw_os_error(libc::EMFILE))
                }),
            };
            let (bundles, outcome) =
                attach_target_groups_with(&groups, |_| Some(7), mock.leaf()).unwrap();
            assert!(outcome.exhausted, "{case}");
            let failed: Vec<u32> = outcome.failures.iter().map(|(slot, _)| *slot).collect();
            let completed: Vec<u32> = outcome.completed.iter().map(|(slot, _)| *slot).collect();
            assert_eq!(failed, expected_failures, "{case}");
            assert_eq!(completed, expected_completed, "{case}");
            assert!(
                outcome.failures[0]
                    .1
                    .starts_with(&format!("fd table exhausted attaching slot {}", failed[0])),
                "{case}: {}",
                outcome.failures[0].1
            );
            for (slot, reason) in &outcome.failures[1..] {
                assert!(
                    reason.contains(&format!("before slot {slot} was fully attached")),
                    "{case}: slot {slot} must fail explicitly: {reason}"
                );
            }
            // A kept bundle belongs wholly to completed or wholly to failed
            // members, so callers detach it whole without a group rebuild.
            for bundle in &bundles {
                let all_completed = bundle.slots.iter().all(|slot| completed.contains(slot));
                let all_failed = bundle.slots.iter().all(|slot| failed.contains(slot));
                assert!(
                    all_completed || all_failed,
                    "{case}: split bundle {:?}",
                    bundle.slots
                );
            }
        }
    }

    #[test]
    fn multi_unsupported_aborts_with_the_fallback_sentinel() {
        let (slots, targets) = two_groups();
        let groups = group_static_slots(&slots, CapturePolicy::Allowlisted, false, &targets);
        for errno in [libc::ENOTSUP, libc::EOPNOTSUPP] {
            let mock = MockGroup {
                calls: std::cell::RefCell::new(Vec::new()),
                fail: Box::new(move |_, _, _| Some(io::Error::from_raw_os_error(errno))),
            };
            let error = attach_target_groups_with(&groups, |_| Some(7), mock.leaf()).unwrap_err();
            assert!(
                format!("{error}").contains("multi-uprobe unsupported"),
                "unexpected sentinel text: {error}"
            );
            assert_eq!(mock.calls.borrow().len(), 1);
        }
    }

    #[test]
    fn multi_unsupported_on_entry_side_still_aborts() {
        let (slots, targets) = two_groups();
        let groups = group_static_slots(&slots, CapturePolicy::Allowlisted, false, &targets);
        let mock = MockGroup {
            calls: std::cell::RefCell::new(Vec::new()),
            fail: Box::new(|_, _, is_return| {
                if !is_return {
                    Some(io::Error::from_raw_os_error(libc::ENOTSUP))
                } else {
                    None
                }
            }),
        };
        let error = attach_target_groups_with(&groups, |_| Some(7), mock.leaf()).unwrap_err();
        assert!(format!("{error}").contains("multi-uprobe unsupported"));
        // Return linked, then the entry side proved the kernel lacks multi.
        assert_eq!(mock.calls.borrow().len(), 2);
    }

    fn multi_link(program: &'static str, slots: Vec<u32>) -> RegisteredLink {
        RegisteredLink::MultiUProbe {
            program,
            slots,
            fds: Vec::new(),
        }
    }

    #[test]
    fn multi_link_registry_reports_members_program_and_no_context() {
        let link = multi_link("p11_entry", vec![3, 7]);
        assert_eq!(link.slots(), &[3, 7]);
        assert!(matches!(
            link.producer(),
            ProducerProgram::UProbe("p11_entry")
        ));
        assert_eq!(link.context(), None);
        let link = multi_link("p11_return", vec![9]);
        assert!(matches!(
            link.producer(),
            ProducerProgram::UProbe("p11_return")
        ));
    }

    #[test]
    fn partial_multi_member_detected_whole_bundle_is_not() {
        let links = vec![multi_link("p11_return", vec![3, 7])];
        assert_eq!(
            find_partial_multi_member(&links, &BTreeSet::from([7, 9])),
            Some(7)
        );
        assert_eq!(
            find_partial_multi_member(&links, &BTreeSet::from([3, 7])),
            None
        );
        assert_eq!(
            find_partial_multi_member(&links, &BTreeSet::from([9])),
            None
        );
        assert_eq!(find_partial_multi_member(&[], &BTreeSet::from([7])), None);
    }

    #[test]
    fn slot_coverage_sees_multi_members() {
        let links = vec![multi_link("p11_return", vec![3, 7])];
        assert!(links_cover_slot(&links, 7));
        assert!(!links_cover_slot(&links, 9));
        assert!(!links_cover_slot(&[], 7));
    }

    #[test]
    fn rebuild_closure_collects_every_affected_member() {
        let links = vec![
            multi_link("p11_return", vec![0, 1, 2]),
            multi_link("p11_entry", vec![0, 1, 2]),
            multi_link("p11_return", vec![5, 6]),
            multi_link("p11_entry", vec![5, 6]),
        ];
        assert_eq!(
            plan_group_rebuild(&links, &BTreeSet::from([1])),
            Some(BTreeSet::from([0, 1, 2])),
            "a partially retired group rebuilds every member, survivors included"
        );
        assert_eq!(
            plan_group_rebuild(&links, &BTreeSet::from([0, 1, 2])),
            None,
            "a wholly retired bundle detaches with no rebuild"
        );
        assert_eq!(
            plan_group_rebuild(&links, &BTreeSet::from([9])),
            None,
            "an unlinked slot never triggers a rebuild"
        );
        assert_eq!(
            plan_group_rebuild(&links, &BTreeSet::new()),
            None,
            "an empty retirement never triggers a rebuild"
        );
        assert_eq!(
            plan_group_rebuild(&[], &BTreeSet::from([1])),
            None,
            "no links means no groups to rebuild"
        );
    }

    #[test]
    fn rebuild_closure_follows_entry_subset_bundles() {
        // An entry-refused member left the return bundle wider than the
        // entry bundle; retiring the refused member still rebuilds the
        // entry side that shares its surviving sibling.
        let links = vec![
            multi_link("p11_return", vec![0, 1]),
            multi_link("p11_entry", vec![0]),
        ];
        assert_eq!(
            plan_group_rebuild(&links, &BTreeSet::from([1])),
            Some(BTreeSet::from([0, 1]))
        );
    }

    #[test]
    fn rebuild_closure_is_transitive_over_overlapping_bundles() {
        let links = vec![
            multi_link("p11_return", vec![0, 1]),
            multi_link("p11_return", vec![1, 2]),
        ];
        assert_eq!(
            plan_group_rebuild(&links, &BTreeSet::from([0])),
            Some(BTreeSet::from([0, 1, 2]))
        );
    }

    #[test]
    fn affected_group_count_covers_disturbed_bundles_once() {
        let links = vec![
            multi_link("p11_return", vec![0, 1, 2]),
            multi_link("p11_entry", vec![0, 1]),
            multi_link("p11_return", vec![5, 6]),
            multi_link("p11_entry", vec![5, 6]),
        ];
        assert_eq!(
            affected_group_count(&links, &BTreeSet::from([0, 1, 2])),
            1,
            "both sides of one group count once"
        );
        assert_eq!(
            affected_group_count(&links, &BTreeSet::from([1, 5])),
            2,
            "members from two groups count both"
        );
        assert_eq!(
            affected_group_count(&links, &BTreeSet::from([9])),
            0,
            "unlinked members disturb no group"
        );
    }

    type DropRecord = std::rc::Rc<std::cell::RefCell<Vec<Vec<String>>>>;

    fn rebuild_drops() -> (DropRecord, impl FnMut(Vec<MultiLinkBundle<MockLink>>)) {
        let drops = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let record = {
            let drops = std::rc::Rc::clone(&drops);
            move |bundles: Vec<MultiLinkBundle<MockLink>>| {
                drops.borrow_mut().push(
                    bundles
                        .iter()
                        .map(|bundle| bundle.program.to_string())
                        .collect(),
                );
            }
        };
        (drops, record)
    }

    #[test]
    fn reattach_all_good_returns_before_entries_with_completions() {
        let (slots, targets) = two_groups();
        let groups = group_static_slots(&slots, CapturePolicy::Allowlisted, false, &targets);
        let mock = MockGroup {
            calls: std::cell::RefCell::new(Vec::new()),
            fail: Box::new(|_, _, _| None),
        };
        let (drops, record) = rebuild_drops();
        let (bundles, outcome) =
            reattach_rebuilt_groups_with(&groups, |_| Some(9), mock.leaf(), record);
        assert_eq!(bundles.len(), 4);
        assert_eq!(outcome.successful.len(), 8);
        assert!(outcome.failures.is_empty());
        assert_eq!(outcome.completed.len(), 4);
        assert!(
            outcome.completed.iter().all(|(_, at)| *at == Some(9)),
            "reactivation carries the clock"
        );
        assert!(drops.borrow().is_empty(), "no rollback without a partial");
        assert_eq!(mock.calls.borrow().len(), 4);
    }

    #[test]
    fn reattach_entry_partial_drops_member_and_reattaches_the_rest() {
        let (slots, targets) = two_groups();
        let groups = group_static_slots(&slots, CapturePolicy::Allowlisted, false, &targets);
        let poison = grouped_offset(&groups, 1);
        let mock = MockGroup {
            calls: std::cell::RefCell::new(Vec::new()),
            fail: Box::new(move |_, sites, is_return| {
                if !is_return && sites.iter().any(|(offset, _)| *offset == poison) {
                    Some(io::Error::from_raw_os_error(libc::EINVAL))
                } else {
                    None
                }
            }),
        };
        let (drops, record) = rebuild_drops();
        let (bundles, outcome) =
            reattach_rebuilt_groups_with(&groups, |_| Some(9), mock.leaf(), record);
        assert_eq!(outcome.failures.len(), 1);
        assert_eq!(outcome.failures[0].0, 1);
        assert!(
            outcome.failures[0]
                .1
                .starts_with("p11_entry at /a.so+0x18: "),
            "unexpected failure: {}",
            outcome.failures[0].1
        );
        let completed: BTreeSet<u32> = outcome.completed.iter().map(|(slot, _)| *slot).collect();
        assert_eq!(completed, BTreeSet::from([0, 2, 3]));
        assert_eq!(
            outcome.successful.len(),
            6,
            "only kept links count as successful"
        );
        // The dirty round's bundles drop entries-first; the clean group is
        // never detached and the failed member leaves no link behind.
        assert_eq!(drops.borrow().len(), 1);
        assert_eq!(
            drops.borrow()[0],
            vec!["p11_entry".to_string(), "p11_return".to_string()],
            "one rollback round, entries before returns"
        );
        assert_eq!(bundles.len(), 4);
        for bundle in &bundles {
            assert!(
                !bundle.slots.contains(&1),
                "slot 1 keeps no rebuilt link: {bundle:?}"
            );
        }
        let group_b: Vec<_> = bundles
            .iter()
            .filter(|bundle| bundle.slots == vec![2, 3])
            .collect();
        assert_eq!(group_b.len(), 2, "group B attaches once and is kept");
        assert!(
            !outcome.successful.contains(&(1, ProbeSide::Return)),
            "the dropped return endpoint is not reported successful"
        );
        let returns = mock
            .calls
            .borrow()
            .iter()
            .filter(|(_, is_return, _)| *is_return)
            .count();
        assert_eq!(
            returns, 3,
            "group A retries its return once, group B attaches once"
        );
    }

    /// F-45: a member whose return was refused in a dirty round (another
    /// member was entry-partial) is not re-rounded, so its refusal is
    /// recorded once — not again with every retry of the remainder.
    #[test]
    fn reattach_records_a_return_refusal_once_beside_an_entry_partial() {
        let (slots, targets) = two_groups();
        let groups = group_static_slots(&slots, CapturePolicy::Allowlisted, false, &targets);
        let return_poison = grouped_offset(&groups, 0);
        let entry_poison = grouped_offset(&groups, 1);
        let mock = MockGroup {
            calls: std::cell::RefCell::new(Vec::new()),
            fail: Box::new(move |_, sites, is_return| {
                let poison = if is_return {
                    return_poison
                } else {
                    entry_poison
                };
                sites
                    .iter()
                    .any(|(offset, _)| *offset == poison)
                    .then(|| io::Error::from_raw_os_error(libc::EINVAL))
            }),
        };
        let (_drops, record) = rebuild_drops();
        let (bundles, outcome) =
            reattach_rebuilt_groups_with(&groups, |_| Some(9), mock.leaf(), record);
        let failed: Vec<u32> = outcome.failures.iter().map(|(slot, _)| *slot).collect();
        assert_eq!(
            failed,
            vec![0, 1],
            "one failure per refused member: {:?}",
            outcome.failures
        );
        let completed: BTreeSet<u32> = outcome.completed.iter().map(|(slot, _)| *slot).collect();
        assert_eq!(completed, BTreeSet::from([2, 3]));
        for bundle in &bundles {
            assert!(
                !bundle.slots.contains(&0) && !bundle.slots.contains(&1),
                "no refused member keeps a link: {bundle:?}"
            );
        }
    }

    #[test]
    fn reattach_return_poison_fails_member_without_entry_attempt() {
        let (slots, targets) = two_groups();
        let groups = group_static_slots(&slots, CapturePolicy::Allowlisted, false, &targets);
        let poison = grouped_offset(&groups, 3);
        let mock = MockGroup {
            calls: std::cell::RefCell::new(Vec::new()),
            fail: Box::new(move |_, sites, is_return| {
                if is_return && sites.iter().any(|(offset, _)| *offset == poison) {
                    Some(io::Error::from_raw_os_error(libc::EINVAL))
                } else {
                    None
                }
            }),
        };
        let (drops, record) = rebuild_drops();
        let (bundles, outcome) =
            reattach_rebuilt_groups_with(&groups, |_| Some(9), mock.leaf(), record);
        assert_eq!(outcome.failures.len(), 1);
        assert_eq!(outcome.failures[0].0, 3);
        assert!(
            outcome.failures[0]
                .1
                .starts_with("p11_return at /b.so+0x28: "),
            "unexpected failure: {}",
            outcome.failures[0].1
        );
        let completed: BTreeSet<u32> = outcome.completed.iter().map(|(slot, _)| *slot).collect();
        assert_eq!(completed, BTreeSet::from([0, 1, 2]));
        assert!(
            drops.borrow().is_empty(),
            "a return refusal leaves no partial link to roll back"
        );
        assert!(
            bundles
                .iter()
                .any(|b| b.program == "p11_return" && b.slots == vec![2]),
            "group B return narrows to its survivor: {bundles:?}"
        );
    }

    #[test]
    fn reattach_persistent_entry_poison_terminates_with_no_links() {
        let (slots, targets) = two_groups();
        let groups = group_static_slots(&slots, CapturePolicy::Allowlisted, false, &targets);
        let mock = MockGroup {
            calls: std::cell::RefCell::new(Vec::new()),
            fail: Box::new(|_, _, is_return| {
                if !is_return {
                    Some(io::Error::from_raw_os_error(libc::EINVAL))
                } else {
                    None
                }
            }),
        };
        let (drops, record) = rebuild_drops();
        let (bundles, outcome) =
            reattach_rebuilt_groups_with(&groups, |_| Some(9), mock.leaf(), record);
        assert_eq!(outcome.failures.len(), 4);
        assert!(outcome.completed.is_empty());
        assert!(outcome.successful.is_empty());
        assert!(bundles.is_empty(), "no member keeps a partial link");
        assert_eq!(drops.borrow().len(), 2, "one rollback round per group");
        let returns = mock
            .calls
            .borrow()
            .iter()
            .filter(|(_, is_return, _)| *is_return)
            .count();
        assert_eq!(
            returns, 2,
            "a fully poisoned group never retries its return"
        );
    }

    #[test]
    fn reattach_exhaustion_stops_with_explicit_remainder() {
        let (slots, targets) = two_groups();
        let groups = group_static_slots(&slots, CapturePolicy::Allowlisted, false, &targets);
        let mock = MockGroup {
            calls: std::cell::RefCell::new(Vec::new()),
            fail: Box::new(|_, _, is_return| {
                if !is_return {
                    Some(io::Error::from_raw_os_error(libc::EMFILE))
                } else {
                    None
                }
            }),
        };
        let (drops, record) = rebuild_drops();
        let (bundles, outcome) =
            reattach_rebuilt_groups_with(&groups, |_| Some(9), mock.leaf(), record);
        assert_eq!(outcome.failures.len(), 4);
        assert_eq!(outcome.failures[0].0, 0);
        assert!(
            outcome.failures[0].1.contains("fd table exhausted"),
            "first failure keeps the shared summary: {}",
            outcome.failures[0].1
        );
        for (slot, reason) in outcome.failures.iter().skip(1) {
            assert!(
                reason.contains("was not reattached"),
                "slot {slot} is explicitly unattempted, never silent: {reason}"
            );
        }
        assert!(outcome.completed.is_empty());
        assert!(bundles.is_empty(), "the exhausted round keeps no links");
        assert_eq!(drops.borrow().len(), 1);
        assert!(
            mock.calls
                .borrow()
                .iter()
                .all(|(_, _, sites)| sites.iter().all(|(offset, _)| *offset < 0x20)),
            "group B is never attempted after exhaustion"
        );
    }

    #[test]
    fn reattach_unsupported_aborts_every_remaining_member() {
        let (slots, targets) = two_groups();
        let groups = group_static_slots(&slots, CapturePolicy::Allowlisted, false, &targets);
        let mock = MockGroup {
            calls: std::cell::RefCell::new(Vec::new()),
            fail: Box::new(|_, _, _| Some(io::Error::from_raw_os_error(libc::ENOTSUP))),
        };
        let (drops, record) = rebuild_drops();
        let (bundles, outcome) =
            reattach_rebuilt_groups_with(&groups, |_| Some(9), mock.leaf(), record);
        assert_eq!(outcome.failures.len(), 4);
        for (slot, reason) in &outcome.failures {
            assert!(
                reason.contains("multi-uprobe unsupported"),
                "slot {slot} names the abort: {reason}"
            );
        }
        assert!(outcome.completed.is_empty());
        assert!(bundles.is_empty());
        assert!(drops.borrow().is_empty());
        assert_eq!(mock.calls.borrow().len(), 1);
    }

    fn retained_target(index: u32, path: &str) -> RetainedStaticTarget {
        let slot = group_slot(index, 1, SlotSemantics::COUNT_ONLY);
        let targets = group_targets(&[(index, path, ElfAbi::Lp64)]);
        let (path, abi) = targets.get(&index).cloned().unwrap();
        RetainedStaticTarget { slot, path, abi }
    }

    #[test]
    fn retention_keeps_exact_facts_for_linked_slots_only() {
        let slots = vec![
            group_slot(0, 1, SlotSemantics::COUNT_ONLY),
            group_slot(1, 1, SlotSemantics::COUNT_ONLY),
            group_slot(2, 1, SlotSemantics::COUNT_ONLY),
        ];
        let targets = group_targets(&[
            (0, "/a.so", ElfAbi::Lp64),
            (1, "/a.so", ElfAbi::Lp64),
            (2, "/a.so", ElfAbi::Lp64),
        ]);
        let successful = BTreeSet::from([(0, ProbeSide::Return), (0, ProbeSide::Entry)]);
        let mut retained = BTreeMap::new();
        retain_from_successful(&mut retained, &slots, &targets, &successful);
        assert_eq!(retained.keys().copied().collect::<Vec<_>>(), vec![0]);
        let kept = retained.get(&0).unwrap();
        assert_eq!(kept.slot, slots[0]);
        assert_eq!(kept.path, PathBuf::from("/a.so"));
        assert_eq!(kept.abi, ElfAbi::Lp64);
    }

    #[test]
    fn retention_overwrites_stale_descriptors_on_reattach() {
        let slots = vec![group_slot(0, 1, SlotSemantics::COUNT_ONLY)];
        let targets = group_targets(&[(0, "/a.so", ElfAbi::Lp64)]);
        let mut retained = BTreeMap::from([(0, retained_target(0, "/a.so"))]);
        retained.get_mut(&0).unwrap().slot.descriptor_index = 5;
        let successful = BTreeSet::from([(0, ProbeSide::Return), (0, ProbeSide::Entry)]);
        retain_from_successful(&mut retained, &slots, &targets, &successful);
        assert_eq!(
            retained.get(&0).unwrap().slot.descriptor_index,
            slots[0].descriptor_index,
            "reattach replaces the frozen descriptor it superseded"
        );
    }

    #[test]
    fn prune_drops_facts_for_linkless_slots() {
        let mut retained = BTreeMap::from([
            (0, retained_target(0, "/a.so")),
            (1, retained_target(1, "/a.so")),
            (2, retained_target(2, "/a.so")),
        ]);
        let links = vec![multi_link("p11_return", vec![0, 1])];
        prune_linkless_retained(&mut retained, &links);
        assert_eq!(
            retained.keys().copied().collect::<Vec<_>>(),
            vec![0, 1],
            "facts survive exactly while a link does"
        );
    }

    #[test]
    fn template_semantics_route_to_their_template_group() {
        let template = SlotSemantics {
            template0_arg: 1,
            ..SlotSemantics::COUNT_ONLY
        };
        let slots = vec![
            group_slot(0, 1, SlotSemantics::COUNT_ONLY),
            group_slot(1, 1, template),
        ];
        let targets = group_targets(&[(0, "/a.so", ElfAbi::Lp64), (1, "/a.so", ElfAbi::Lp64)]);
        let groups = group_static_slots(
            &slots,
            CapturePolicy::UnsafeUnvalidatedMetadata,
            false,
            &targets,
        );
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].entry_program, "p11_entry");
        assert_eq!(group_member_indices(&groups[0]), vec![0]);
        assert_eq!(groups[1].entry_program, "p11_entry_template");
        assert_eq!(group_member_indices(&groups[1]), vec![1]);
    }

    #[test]
    fn only_static_slot_programs_have_endpoint_identities() {
        assert_eq!(
            static_endpoint("p11_return", 7),
            Some((7, ProbeSide::Return))
        );
        for program in [
            "p11_entry",
            "p11_entry_ia32",
            "p11_entry_template",
            "p11_entry_template_types",
            "p11_entry_template_pair",
        ] {
            assert_eq!(static_endpoint(program, 7), Some((7, ProbeSide::Entry)));
        }
        for program in [
            "dl_debug_state",
            "function_list_entry",
            "function_list_return",
            "interface_list_entry",
            "interface_list_return",
            "interface_entry",
            "interface_return",
            "task_newtask",
            "sched_process_exec",
            "sched_process_exit",
        ] {
            assert_eq!(static_endpoint(program, 7), None, "{program}");
        }
    }

    #[test]
    fn mandatory_lifecycle_refuses_hook_loss() {
        let mut state = ();
        let outcome = attach_lifecycle_with::<_, ()>(
            &mut state,
            |_, program| {
                assert_eq!(program, "sched_process_exec");
                Err(
                    aya::programs::ProgramError::IOError(io::Error::other("tracefs not found"))
                        .into(),
                )
            },
            |_, _, _| Ok(()),
        );
        assert!(outcome.is_err());
    }

    #[test]
    fn process_creation_infrastructure_is_mandatory_in_every_scope() {
        let cgroup = Scope::Cgroup {
            id: 1,
            path: "/".into(),
            dir: Arc::new(File::open("/").unwrap()),
        };
        for (scope, policy, expected) in [
            (Scope::Pid(7), CapturePolicy::Allowlisted, true),
            (
                Scope::Pid(7),
                CapturePolicy::UnsafeUnvalidatedMetadata,
                true,
            ),
            (Scope::Pid(7), CapturePolicy::AggregateOnly, true),
            (cgroup, CapturePolicy::Allowlisted, true),
        ] {
            assert_eq!(process_creation_capture_enabled(&scope, policy), expected);
        }
    }

    #[test]
    fn dynamic_export_snapshot_is_exact_and_deduplicates_the_link_pair() {
        let context = LoaderContextId::from_case_id(0);
        let other = LoaderContextId::from_case_id(1);
        let exact = DynamicExportIdentity {
            object: PinnedObjectId(7),
            file_offset: 0x10,
            cookie: 3,
            abi: HookAbi::FunctionList,
        };
        let different = DynamicExportIdentity {
            file_offset: 0x20,
            ..exact
        };
        let links = [
            (context, Some(exact)),
            (context, Some(exact)),
            (context, Some(different)),
            (other, Some(exact)),
            (context, None),
        ];

        let snapshot = dynamic_export_snapshot_with(&links, context, |link| *link);

        assert_eq!(snapshot, [exact, different]);
    }

    #[test]
    fn discovery_counter_snapshots_are_absolute_and_regressions_fail_closed() {
        let cells: [&[u64]; 5] = [&[1, 2], &[3, 4], &[5, 6], &[7, 8], &[9, 10]];
        let first = counter_snapshot_with(
            |index| {
                Ok(cells[index as usize]
                    .iter()
                    .copied()
                    .fold(0u64, u64::saturating_add))
            },
            2,
        )
        .unwrap();
        assert_eq!(first.ring_loss, 3);
        assert_eq!(first.export_state_failures, 7);
        assert_eq!(first.export_bounded_read_failures, 11);
        assert_eq!(first.loader_hits, 15);
        assert_eq!(first.loader_state_read_failures, 19);
        assert_eq!(first.abi_refusals, 2);

        let mut retained = CounterSnapshot::default();
        assert!(retained.replace_with(first));
        assert_eq!(retained, first);
        let cells: [&[u64]; 5] = [&[2, 2], &[4, 4], &[6, 6], &[8, 8], &[10, 10]];
        let next = counter_snapshot_with(
            |index| {
                Ok(cells[index as usize]
                    .iter()
                    .copied()
                    .fold(0u64, u64::saturating_add))
            },
            3,
        )
        .unwrap();
        assert!(retained.replace_with(next));
        assert_eq!(retained.abi_refusals, 3);
        assert_eq!(
            retained.loader_hits, 16,
            "absolute values are replaced, not added"
        );

        let decreased = CounterSnapshot {
            ring_loss: next.ring_loss - 1,
            ..next
        };
        assert!(!retained.replace_with(decreased));
        assert!(!retained.replace_with(CounterSnapshot {
            abi_refusals: next.abi_refusals - 1,
            ..next
        }));
        assert_eq!(
            retained, next,
            "a regressing cell retains the prior authority"
        );
    }

    #[test]
    fn return_failure_suppresses_its_entry_without_blocking_another_slot() {
        for (object_has_unsafe, target_abi, expected_entry) in [
            (false, ElfAbi::Lp64, "p11_entry"),
            (true, ElfAbi::Ilp32, "p11_entry_ia32"),
        ] {
            let slots = [test_slot(0), test_slot(1)];
            let mut attempted = Vec::new();
            let outcome = attach_targets_with(
                &slots,
                CapturePolicy::Allowlisted,
                object_has_unsafe,
                |_| Ok(target_abi),
                |program, slot, _| {
                    attempted.push((program, slot.index));
                    if program == "p11_return" && slot.index == 0 {
                        anyhow::bail!("injected return failure")
                    }
                    Ok(())
                },
                |_| Some(10),
            )
            .unwrap();

            assert_eq!(
                outcome.successful,
                [(1, ProbeSide::Return), (1, ProbeSide::Entry)]
                    .into_iter()
                    .collect(),
                "slot 1 gets its entry/return pair"
            );
            assert_eq!(outcome.failures.len(), 1);
            assert_eq!(outcome.failures[0].0, 0);
            assert_eq!(outcome.completed, [(1, Some(10))]);
            assert_eq!(
                attempted,
                [("p11_return", 0), ("p11_return", 1), (expected_entry, 1),]
            );
        }
    }

    #[test]
    fn fd_exhaustion_stops_further_attach_with_one_summary() {
        let slots = [test_slot(0), test_slot(1), test_slot(2)];
        let mut attempted = Vec::new();
        let outcome = attach_targets_with(
            &slots,
            CapturePolicy::Allowlisted,
            false,
            |_| Ok(ElfAbi::Lp64),
            |program, slot, _| {
                attempted.push((program, slot.index));
                if slot.index == 1 {
                    let exhausted = std::io::Error::from_raw_os_error(libc::EMFILE);
                    return Err(anyhow::Error::new(exhausted).context("bpf_link_create failed"));
                }
                Ok(())
            },
            |_| Some(10),
        )
        .unwrap();

        assert_eq!(attempted, [("p11_return", 0), ("p11_return", 1)]);
        assert!(outcome.exhausted);
        // One summary first, then every unfinished slot explicitly: slot 0
        // keeps only a return link and slot 2 was never attempted.
        assert_eq!(
            outcome
                .failures
                .iter()
                .map(|(slot, _)| *slot)
                .collect::<Vec<_>>(),
            [1, 0, 2]
        );
        assert_eq!(outcome.failures[0].0, 1);
        for (slot, reason) in &outcome.failures[1..] {
            assert!(
                reason.contains(&format!("before slot {slot} was fully attached")),
                "slot {slot} must fail explicitly: {reason}"
            );
        }
        assert!(
            outcome.failures[0]
                .1
                .contains("fd table exhausted attaching slot 1"),
            "unexpected summary: {}",
            outcome.failures[0].1
        );
        assert!(
            outcome.failures[0].1.contains("ulimit -n"),
            "summary must name the remedy: {}",
            outcome.failures[0].1
        );
    }

    fn aya_attach_errno(errno: i32) -> aya::programs::ProgramError {
        aya::programs::ProgramError::SyscallError(aya::sys::SyscallError {
            call: "perf_event_open",
            io_error: io::Error::from_raw_os_error(errno),
        })
    }

    #[test]
    fn static_attach_context_preserves_aya_errno() {
        let error =
            static_attach_error("p11_return", &test_slot(2), aya_attach_errno(libc::EMFILE));
        assert!(
            is_fd_exhaustion(&error),
            "Aya's typed EMFILE must survive: {error:#}"
        );
        assert!(
            error
                .to_string()
                .contains("p11_return at /proc/self/fd/42+0x20")
        );
        assert!(error.chain().any(|cause| {
            cause
                .downcast_ref::<aya::programs::ProgramError>()
                .is_some()
        }));
    }

    #[test]
    fn typed_aya_fd_exhaustion_stops_return_and_entry_passes() {
        for (failed_program, failed_slot) in [("p11_return", 2), ("p11_entry", 1)] {
            let slots = [test_slot(0), test_slot(1), test_slot(2), test_slot(3)];
            let mut attempted = Vec::new();
            let mut completions = Vec::new();
            let outcome = attach_targets_with(
                &slots,
                CapturePolicy::Allowlisted,
                false,
                |_| Ok(ElfAbi::Lp64),
                |program, slot, _| {
                    attempted.push((program, slot.index));
                    if program == failed_program && slot.index == failed_slot {
                        return Err(static_attach_error(
                            program,
                            slot,
                            aya_attach_errno(libc::EMFILE),
                        ));
                    }
                    Ok(())
                },
                |slot| {
                    completions.push(slot.index);
                    Some(100 + u64::from(slot.index))
                },
            )
            .unwrap();

            assert!(
                outcome.exhausted,
                "{failed_program} must stop after typed Aya EMFILE"
            );
            // The summary is first; every unfinished slot follows explicitly.
            let expected_failures: &[u32] = if failed_program == "p11_return" {
                &[2, 0, 1, 3]
            } else {
                &[1, 2, 3]
            };
            assert_eq!(
                outcome
                    .failures
                    .iter()
                    .map(|(slot, _)| *slot)
                    .collect::<Vec<_>>(),
                expected_failures
            );
            assert_eq!(outcome.failures[0].0, failed_slot);
            assert!(outcome.failures[0].1.contains("fd table exhausted"));
            assert!(
                outcome.failures[0].1.contains("perf_event_open"),
                "original cause lost: {}",
                outcome.failures[0].1
            );
            assert!(outcome.failures[0].1.contains("/proc/self/fd/42"));
            assert!(
                outcome.failures[0].1.contains("os error 24"),
                "original errno lost: {}",
                outcome.failures[0].1
            );
            if failed_program == "p11_return" {
                assert_eq!(
                    attempted,
                    [("p11_return", 0), ("p11_return", 1), ("p11_return", 2)]
                );
                assert_eq!(
                    outcome.successful,
                    [(0, ProbeSide::Return), (1, ProbeSide::Return)]
                        .into_iter()
                        .collect()
                );
                assert!(outcome.completed.is_empty());
                assert!(completions.is_empty());
            } else {
                assert_eq!(
                    attempted,
                    [
                        ("p11_return", 0),
                        ("p11_return", 1),
                        ("p11_return", 2),
                        ("p11_return", 3),
                        ("p11_entry", 0),
                        ("p11_entry", 1)
                    ]
                );
                assert_eq!(
                    outcome.successful,
                    [
                        (0, ProbeSide::Return),
                        (1, ProbeSide::Return),
                        (2, ProbeSide::Return),
                        (3, ProbeSide::Return),
                        (0, ProbeSide::Entry)
                    ]
                    .into_iter()
                    .collect()
                );
                assert_eq!(outcome.completed, [(0, Some(100))]);
                assert_eq!(completions, [0]);
            }
        }
    }

    #[test]
    fn typed_aya_fd_exhaustion_fails_every_unfinished_slot_explicitly() {
        // Callers detach and deactivate exactly the failed indices. After an
        // exhaustion stop, a slot left out of both lists would stay active and
        // link-less, or keep a return that can never pair with an entry.
        for (object_has_unsafe, failed_program, failed_slot) in [
            (false, "p11_return", 0),
            (false, "p11_return", 2),
            (false, "p11_return", 3),
            (false, "p11_entry", 0),
            (false, "p11_entry", 1),
            (false, "p11_entry", 3),
            // Unsafe objects select one of several entry programs per slot; any
            // entry-side exhaustion must still settle every slot.
            (true, "p11_return", 1),
            (true, "entry", 0),
            (true, "entry", 2),
        ] {
            let slots = [test_slot(0), test_slot(1), test_slot(2), test_slot(3)];
            let outcome = attach_targets_with(
                &slots,
                CapturePolicy::Allowlisted,
                object_has_unsafe,
                |_| Ok(ElfAbi::Lp64),
                |program, slot, _| {
                    let failing = if failed_program == "entry" {
                        program != "p11_return"
                    } else {
                        program == failed_program
                    };
                    if failing && slot.index == failed_slot {
                        return Err(static_attach_error(
                            program,
                            slot,
                            aya_attach_errno(libc::EMFILE),
                        ));
                    }
                    Ok(())
                },
                |slot| Some(100 + u64::from(slot.index)),
            )
            .unwrap();

            let case = format!(
                "{failed_program} exhausted at slot {failed_slot} (unsafe object: {object_has_unsafe})"
            );
            assert!(outcome.exhausted, "{case}");
            assert_eq!(outcome.failures[0].0, failed_slot, "{case}");
            assert!(
                outcome.failures[0]
                    .1
                    .contains(&format!("fd table exhausted attaching slot {failed_slot}")),
                "{case}: the summary stays first: {}",
                outcome.failures[0].1
            );
            let completed: BTreeSet<u32> =
                outcome.completed.iter().map(|(slot, _)| *slot).collect();
            let failed: Vec<u32> = outcome.failures.iter().map(|(slot, _)| *slot).collect();
            let failed_set: BTreeSet<u32> = failed.iter().copied().collect();
            assert_eq!(
                failed.len(),
                failed_set.len(),
                "{case}: one record per slot"
            );
            assert!(completed.is_disjoint(&failed_set), "{case}");
            assert_eq!(
                completed
                    .union(&failed_set)
                    .copied()
                    .collect::<BTreeSet<_>>(),
                (0..4).collect(),
                "{case}: every slot is a completed pair or an explicit failure"
            );
            for (slot, reason) in &outcome.failures[1..] {
                assert!(
                    reason.contains(&format!(
                        "fd table exhausted before slot {slot} was fully attached"
                    )) && reason.contains("ulimit -n"),
                    "{case}: slot {slot} must fail explicitly, never silently: {reason}"
                );
            }
            // Every retained link belongs to a completed pair or to a failed
            // slot that the caller now detaches; nothing is orphaned.
            for (slot, _) in &outcome.successful {
                assert!(
                    completed.contains(slot) || failed_set.contains(slot),
                    "{case}: link for slot {slot} has no owner"
                );
            }
        }
    }

    #[test]
    fn emfile_text_without_typed_errno_continues_per_slot() {
        let mut attempted = Vec::new();
        let outcome = attach_targets_with(
            &[test_slot(0), test_slot(1)],
            CapturePolicy::Allowlisted,
            false,
            |_| Ok(ElfAbi::Lp64),
            |program, slot, _| {
                attempted.push((program, slot.index));
                if program == "p11_return" && slot.index == 0 {
                    bail!("diagnostic mentions EMFILE, but has no errno cause");
                }
                Ok(())
            },
            |_| Some(10),
        )
        .unwrap();
        assert!(!outcome.exhausted);
        assert_eq!(outcome.failures.len(), 1);
        assert_eq!(
            outcome.successful,
            [(1, ProbeSide::Return), (1, ProbeSide::Entry)]
                .into_iter()
                .collect()
        );
        assert_eq!(outcome.completed, [(1, Some(10))]);
        assert_eq!(
            attempted,
            [("p11_return", 0), ("p11_return", 1), ("p11_entry", 1)]
        );
    }

    #[test]
    fn typed_aya_einval_continues_per_slot() {
        let mut attempted = Vec::new();
        let outcome = attach_targets_with(
            &[test_slot(0), test_slot(1)],
            CapturePolicy::Allowlisted,
            false,
            |_| Ok(ElfAbi::Lp64),
            |program, slot, _| {
                attempted.push((program, slot.index));
                if program == "p11_return" && slot.index == 0 {
                    return Err(static_attach_error(
                        program,
                        slot,
                        aya_attach_errno(libc::EINVAL),
                    ));
                }
                Ok(())
            },
            |_| Some(10),
        )
        .unwrap();
        assert!(!outcome.exhausted);
        assert_eq!(outcome.failures.len(), 1);
        assert!(outcome.failures[0].1.contains("perf_event_open"));
        assert_eq!(
            outcome.successful,
            [(1, ProbeSide::Return), (1, ProbeSide::Entry)]
                .into_iter()
                .collect()
        );
        assert_eq!(outcome.completed, [(1, Some(10))]);
        assert_eq!(
            attempted,
            [("p11_return", 0), ("p11_return", 1), ("p11_entry", 1)]
        );
    }

    #[test]
    fn diagnostic_mixed_targets_select_one_width_matched_entry_each() {
        let mut dependency = test_slot(1);
        dependency.object = PinnedObjectId(1);
        let slots = [test_slot(0), dependency];
        let mut attempted = Vec::new();
        let outcome = attach_targets_with(
            &slots,
            CapturePolicy::Allowlisted,
            true,
            |slot| {
                Ok(if slot.object == crate::plan::TEST_PINNED_OBJECT {
                    ElfAbi::Lp64
                } else {
                    ElfAbi::Ilp32
                })
            },
            |program, slot, _| {
                attempted.push((program, slot.index));
                Ok(())
            },
            |_| Some(10),
        )
        .unwrap();

        assert_eq!(
            attempted,
            [
                ("p11_return", 0),
                ("p11_return", 1),
                ("p11_entry", 0),
                ("p11_entry_ia32", 1),
            ]
        );
        assert_eq!(outcome.completed, [(0, Some(10)), (1, Some(10))]);
    }

    #[test]
    fn missing_pinned_target_abi_refuses_before_any_return_attach() {
        let slots = [test_slot(0), test_slot(1)];
        let mut attempted = Vec::new();
        let error = attach_targets_with(
            &slots,
            CapturePolicy::Allowlisted,
            true,
            |slot| {
                if slot.index == 1 {
                    anyhow::bail!("object was not pinned")
                }
                Ok(ElfAbi::Lp64)
            },
            |program, slot, _| {
                attempted.push((program, slot.index));
                Ok(())
            },
            |_| Some(10),
        )
        .unwrap_err();

        assert_eq!(error.to_string(), "object was not pinned");
        assert!(attempted.is_empty());
    }

    #[test]
    fn entry_failure_records_only_the_successful_return_endpoint() {
        let outcome = attach_targets_with(
            &[test_slot(0)],
            CapturePolicy::Allowlisted,
            false,
            |_| Ok(ElfAbi::Lp64),
            |program, _, _| {
                if program == "p11_entry" {
                    anyhow::bail!("injected entry failure")
                }
                Ok(())
            },
            |_| Some(10),
        )
        .unwrap();

        assert_eq!(
            outcome.successful,
            [(0, ProbeSide::Return)].into_iter().collect()
        );
        assert_eq!(outcome.failures.len(), 1);
        assert!(outcome.completed.is_empty());
    }

    #[test]
    fn static_slot_completion_is_timestamped_before_later_slot_work() {
        let slots = [test_slot(0), test_slot(1)];
        let events = std::cell::RefCell::new(Vec::new());
        let timestamp = std::cell::Cell::new(20u64);
        let outcome = attach_targets_with(
            &slots,
            CapturePolicy::Allowlisted,
            false,
            |_| Ok(ElfAbi::Lp64),
            |program, slot, _| {
                events.borrow_mut().push((program, slot.index));
                Ok(())
            },
            |slot: &Slot| {
                let now = timestamp.get();
                timestamp.set(now + 10);
                events.borrow_mut().push(("completed", slot.index));
                Some(now)
            },
        )
        .unwrap();

        assert_eq!(outcome.completed, [(0, Some(20)), (1, Some(30))]);
        assert_eq!(
            *events.borrow(),
            [
                ("p11_return", 0),
                ("p11_return", 1),
                ("p11_entry", 0),
                ("completed", 0),
                ("p11_entry", 1),
                ("completed", 1),
            ],
            "each completion clock is read immediately after its successful slot pair"
        );
    }

    #[test]
    fn replacing_a_slot_does_not_double_count_successful_endpoint_history() {
        let initial = attach_targets_with(
            &[test_slot(0)],
            CapturePolicy::Allowlisted,
            false,
            |_| Ok(ElfAbi::Lp64),
            |_, _, _| Ok(()),
            |_| Some(10),
        )
        .unwrap();
        let mut history = initial.successful;
        assert_eq!(history.len(), 2);

        let replacement = attach_targets_with(
            &[test_slot(0)],
            CapturePolicy::Allowlisted,
            false,
            |_| Ok(ElfAbi::Lp64),
            |_, _, _| Ok(()),
            |_| Some(20),
        )
        .unwrap();
        history.extend(replacement.successful);
        assert_eq!(
            history.len(),
            2,
            "the same slot's return/entry endpoint identities are lifetime-deduplicated"
        );

        let new_slot = attach_targets_with(
            &[test_slot(1)],
            CapturePolicy::Allowlisted,
            false,
            |_| Ok(ElfAbi::Lp64),
            |_, _, _| Ok(()),
            |_| Some(30),
        )
        .unwrap();
        history.extend(new_slot.successful);
        assert_eq!(history.len(), 4);
    }

    #[test]
    fn terminal_detach_orders_every_static_and_dynamic_link_and_keeps_going_after_error() {
        let mut attempted = Vec::new();
        let errors = detach_selected_with(
            vec![
                (ProducerProgram::UProbe("p11_return"), "return-2"),
                (
                    ProducerProgram::UProbe("interface_list_entry"),
                    "interface-list-entry-1",
                ),
                (
                    ProducerProgram::UProbe("interface_list_return"),
                    "interface-list-return-1",
                ),
                (ProducerProgram::BtfTracePoint("task_newtask"), "newtask-2"),
                (
                    ProducerProgram::UProbe("p11_entry_template_pair"),
                    "template-pair-2",
                ),
                (ProducerProgram::UProbe("dl_debug_state"), "loader-1"),
                (ProducerProgram::UProbe("p11_entry"), "lp64-entry-2"),
                (
                    ProducerProgram::UProbe("function_list_entry"),
                    "function-list-entry-1",
                ),
                (
                    ProducerProgram::UProbe("function_list_return"),
                    "function-list-return-1",
                ),
                (
                    ProducerProgram::UProbe("p11_entry_template_types"),
                    "template-types-1",
                ),
                (
                    ProducerProgram::UProbe("interface_entry"),
                    "interface-entry-1",
                ),
                (
                    ProducerProgram::UProbe("interface_return"),
                    "interface-return-1",
                ),
                (ProducerProgram::UProbe("p11_entry_ia32"), "ilp32-entry-1"),
                (ProducerProgram::UProbe("p11_entry_template"), "template-2"),
                (
                    ProducerProgram::UProbe("interface_list_entry"),
                    "interface-list-entry-2",
                ),
                (
                    ProducerProgram::UProbe("interface_list_return"),
                    "interface-list-return-2",
                ),
                (ProducerProgram::UProbe("p11_return"), "return-1"),
                (
                    ProducerProgram::UProbe("p11_entry_template_pair"),
                    "template-pair-1",
                ),
                (ProducerProgram::UProbe("dl_debug_state"), "loader-2"),
                (ProducerProgram::UProbe("p11_entry"), "lp64-entry-1"),
                (
                    ProducerProgram::UProbe("function_list_entry"),
                    "function-list-entry-2",
                ),
                (
                    ProducerProgram::UProbe("function_list_return"),
                    "function-list-return-2",
                ),
                (
                    ProducerProgram::UProbe("p11_entry_template_types"),
                    "template-types-2",
                ),
                (ProducerProgram::BtfTracePoint("task_newtask"), "newtask-1"),
                (
                    ProducerProgram::UProbe("interface_entry"),
                    "interface-entry-2",
                ),
                (
                    ProducerProgram::UProbe("interface_return"),
                    "interface-return-2",
                ),
                (ProducerProgram::UProbe("p11_entry_ia32"), "ilp32-entry-2"),
                (ProducerProgram::UProbe("p11_entry_template"), "template-1"),
            ],
            |link| {
                attempted.push(link);
                if link == "template-types-1" {
                    anyhow::bail!("injected detach failure")
                }
                Ok(())
            },
        );
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].to_string(), "injected detach failure");
        assert_eq!(
            attempted,
            [
                "lp64-entry-2",
                "lp64-entry-1",
                "ilp32-entry-1",
                "ilp32-entry-2",
                "template-2",
                "template-1",
                "template-types-1",
                "template-types-2",
                "template-pair-2",
                "template-pair-1",
                "newtask-2",
                "newtask-1",
                "return-2",
                "return-1",
                "interface-list-entry-1",
                "interface-list-return-1",
                "loader-1",
                "function-list-entry-1",
                "function-list-return-1",
                "interface-entry-1",
                "interface-return-1",
                "interface-list-entry-2",
                "interface-list-return-2",
                "loader-2",
                "function-list-entry-2",
                "function-list-return-2",
                "interface-entry-2",
                "interface-return-2",
            ],
            "every registered link is attempted once and paired entries precede returns"
        );
        assert_eq!(attempted.iter().copied().collect::<BTreeSet<_>>().len(), 28);
    }

    #[test]
    fn immutable_map_inventory_covers_every_authorization_input() {
        assert_eq!(
            BASE_POLICY_MAPS.map(|(name, _)| name),
            [
                "CONFIG",
                "PID_FILTER",
                "CGROUP_FILTER",
                "DESCRIPTORS",
                "ASYNC_FUNCTIONS",
                "MECH_SHAPE",
                "TAIL_CALLS",
                "STACK_GUARD",
            ]
        );
        assert_eq!(
            FEATURE_POLICY_MAPS.map(|(name, _)| name),
            ["ATTR_BOOL_BITS", "PAIR_CALLS"]
        );
        assert_eq!(TAIL_POLICY_MAP, "TAIL_CALLS");
        assert_eq!(PAIR_POLICY_MAP, "PAIR_CALLS");
    }

    #[test]
    fn map_freeze_syscall_attribute_is_only_the_u32_fd() {
        assert_eq!(std::mem::size_of::<BpfMapFreezeAttr>(), 4);
        assert_eq!(std::mem::align_of::<BpfMapFreezeAttr>(), 4);
        assert_eq!(std::mem::offset_of!(BpfMapFreezeAttr, map_fd), 0);
    }

    #[test]
    fn program_array_readback_distinguishes_empty_from_failure() {
        assert_eq!(
            program_array_lookup_result("TAIL_CALLS", 0, 37, Ok(())).unwrap(),
            Some(37)
        );
        assert_eq!(
            program_array_lookup_result(
                "TAIL_CALLS",
                0,
                0,
                Err(std::io::Error::from_raw_os_error(libc::ENOENT)),
            )
            .unwrap(),
            None
        );

        let error = program_array_lookup_result(
            "TAIL_CALLS",
            0,
            0,
            Err(std::io::Error::from_raw_os_error(libc::EPERM)),
        )
        .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("reading back TAIL_CALLS[0]"));
        assert!(rendered.contains("Operation not permitted"));
    }

    #[test]
    fn map_element_lookup_attribute_matches_the_kernel_abi() {
        assert_eq!(std::mem::size_of::<BpfMapElementAttr>(), 32);
        assert_eq!(std::mem::align_of::<BpfMapElementAttr>(), 8);
        assert_eq!(std::mem::offset_of!(BpfMapElementAttr, map_fd), 0);
        assert_eq!(std::mem::offset_of!(BpfMapElementAttr, key), 8);
        assert_eq!(std::mem::offset_of!(BpfMapElementAttr, value), 16);
        assert_eq!(std::mem::offset_of!(BpfMapElementAttr, flags), 24);
    }

    #[test]
    fn safe_capture_entry_program_selection_never_uses_unsafe_templates() {
        let diagnostic = |semantics, policy, abi| entry_program(semantics, policy, true, abi);
        assert_eq!(
            diagnostic(
                &SlotSemantics::COUNT_ONLY,
                CapturePolicy::Allowlisted,
                ElfAbi::Lp64,
            ),
            "p11_entry"
        );
        for policy in [
            CapturePolicy::Allowlisted,
            CapturePolicy::AggregateOnly,
            CapturePolicy::UnsafeUnvalidatedMetadata,
        ] {
            assert_eq!(
                diagnostic(&SlotSemantics::COUNT_ONLY, policy, ElfAbi::Ilp32),
                "p11_entry_ia32"
            );
            assert_eq!(
                entry_program(&SlotSemantics::COUNT_ONLY, policy, false, ElfAbi::Ilp32),
                "p11_entry",
                "the default object keeps its mixed-ABI ordinary entry"
            );
        }

        let mut template = SlotSemantics::COUNT_ONLY;
        template.template0_arg = 1;
        assert_eq!(
            diagnostic(
                &template,
                CapturePolicy::UnsafeUnvalidatedMetadata,
                ElfAbi::Lp64,
            ),
            "p11_entry_template"
        );
        assert_eq!(
            diagnostic(&template, CapturePolicy::Allowlisted, ElfAbi::Lp64),
            "p11_entry"
        );
        assert_eq!(
            diagnostic(&template, CapturePolicy::AggregateOnly, ElfAbi::Lp64),
            "p11_entry"
        );

        let mut second_template = SlotSemantics::COUNT_ONLY;
        second_template.template0_arg = 2;
        second_template.template1_arg = 4;
        assert_eq!(
            diagnostic(
                &second_template,
                CapturePolicy::UnsafeUnvalidatedMetadata,
                ElfAbi::Ilp32,
            ),
            "p11_entry_template_pair"
        );

        let mut types_only = SlotSemantics::COUNT_ONLY;
        types_only.template0_arg = 2;
        types_only.semantic_flags = p11scope_ebpf_common::semantic_flags::TEMPLATE0_TYPES_ONLY;
        assert_eq!(
            diagnostic(
                &types_only,
                CapturePolicy::UnsafeUnvalidatedMetadata,
                ElfAbi::Ilp32,
            ),
            "p11_entry_template_types"
        );

        let mut async_call = SlotSemantics::COUNT_ONLY;
        async_call.async_name_arg = 1;
        assert_ne!(async_call.async_name_arg, ARG_NONE);
        assert_eq!(
            diagnostic(
                &async_call,
                CapturePolicy::UnsafeUnvalidatedMetadata,
                ElfAbi::Ilp32,
            ),
            "p11_entry_ia32"
        );
    }

    #[test]
    fn safe_capture_exact_async_catalog_preserves_ids_and_rejects_unknown_names() {
        let catalog = standard_async_catalog().unwrap();
        let exact = p11scope_ebpf_common::FunctionNameKey::from_bytes(b"C_Encrypt\0").unwrap();
        let unknown = p11scope_ebpf_common::FunctionNameKey::from_bytes(b"C_EncryptX\0").unwrap();

        assert_eq!(catalog.len(), 104);
        assert_eq!(catalog.get(&exact), Some(&30));
        assert_eq!(catalog.get(&unknown), None);
    }

    #[test]
    fn safe_capture_internal_output_correlation_values_do_not_enter_trace_output() {
        let raw_session = 0xdead_beef_cafe_babe;
        let raw_async_id = 0xfeed_face_1234_5678;
        let event = p11scope_ebpf_common::Event {
            session: raw_session,
            async_value: raw_async_id,
            mechanism: p11scope_ebpf_common::MECH_NONE,
            ..p11scope_ebpf_common::Event::default()
        };
        let line = crate::trace::format_line(&event, 0, "C_AsyncGetID", None);

        assert!(!line.contains(&format!("{raw_session:x}")));
        assert!(!line.contains(&format!("{raw_async_id:x}")));
        assert!(!line.contains(&raw_session.to_string()));
        assert!(!line.contains(&raw_async_id.to_string()));
    }

    /// Mutation caught: a caller can bind an owned generation capability to a
    /// cgroup or a different PID before the load/mutation barrier.
    #[test]
    fn pause_capability_is_validated_into_one_private_full_key() {
        let capability = OwnedPauseGeneration {
            tgid: 42,
            generation: std::num::NonZeroU64::new(99).unwrap(),
        };
        assert!(pause_key_for(&Scope::Pid(41), Some(&capability)).is_err());
        let cgroup_dir = tempfile::tempdir().unwrap();
        let cgroup = crate::scope::cgroup(cgroup_dir.path()).unwrap();
        assert!(pause_key_for(&cgroup, Some(&capability)).is_err());
        assert!(pause_key_for(&Scope::System, Some(&capability)).is_err());

        let key = pause_key_for(&Scope::Pid(42), Some(&capability))
            .unwrap()
            .unwrap();
        assert_eq!(key.tgid, 42);
        assert_eq!(key.pad, 0);
        assert_eq!(key.generation_token, 99);
        assert!(pause_key_for(&Scope::Pid(42), None).unwrap().is_none());
    }

    #[test]
    fn scope_kind_reports_the_stable_json_label() {
        assert_eq!(Scope::Pid(7).kind(), "pid");
        let cgroup_dir = tempfile::tempdir().unwrap();
        let cgroup = crate::scope::cgroup(cgroup_dir.path()).unwrap();
        assert_eq!(cgroup.kind(), "cgroup");
        assert_eq!(Scope::System.kind(), "system");
    }

    /// RB-2 capacity contract: every exec and leader exit in a cgroup or
    /// system scope costs one 920-byte record plus the 8-byte ring header,
    /// and the compiled 64 KiB DISCOVERY ring held 70 — a busy host lost
    /// records every frame. A shared scope loads a ring for at least 2,048;
    /// a named process keeps the compiled ring. Ring sizes stay page-sized
    /// powers of two, which the kernel requires.
    #[test]
    fn a_shared_scope_discovery_ring_holds_two_thousand_records() {
        let record = std::mem::size_of::<p11scope_ebpf_common::DiscoveryRecord>() + 8;
        let cgroup_dir = tempfile::tempdir().unwrap();
        let cgroup = crate::scope::cgroup(cgroup_dir.path()).unwrap();
        for scope in [cgroup, Scope::System] {
            let bytes = discovery_ring_bytes(&scope);
            assert!(
                bytes as usize / record >= 2048,
                "{}: {bytes} bytes hold {} records",
                scope.kind(),
                bytes as usize / record
            );
            assert!(bytes.is_power_of_two() && bytes >= 4096);
        }
        assert_eq!(
            discovery_ring_bytes(&Scope::Pid(7)),
            p11scope_ebpf_common::DISCOVERY_BYTES
        );
    }

    fn discovery_items(first: u64, count: u64) -> Vec<events::DiscoveryItem> {
        (first..first + count)
            .map(|ts| {
                let mut record: p11scope_ebpf_common::DiscoveryRecord =
                    unsafe { std::mem::zeroed() };
                record.hook_ts_ns = ts;
                events::DiscoveryItem::Record(record)
            })
            .collect()
    }

    fn stamps(items: &[events::DiscoveryItem]) -> Vec<Option<u64>> {
        items
            .iter()
            .map(|item| match item {
                events::DiscoveryItem::Record(record) => Some(record.hook_ts_ns),
                events::DiscoveryItem::Malformed => None,
            })
            .collect()
    }

    /// RB-2 staging keeps ring order and drops nothing: it stages at most a
    /// quantum per call, stops at its capacity leaving the rest in the ring,
    /// and serves every staged item before anything newer.
    #[test]
    fn discovery_staging_keeps_ring_order_and_leaves_overflow_in_the_ring() {
        let mut ring: std::collections::VecDeque<_> = discovery_items(0, 10).into();
        ring.insert(3, events::DiscoveryItem::Malformed);
        let mut stage = DiscoveryStage::default();

        assert_eq!(stage.stage(4, || ring.pop_front()), 4);
        assert_eq!(stage.stage(100, || ring.pop_front()), 7, "the ring ran dry");
        assert_eq!(stage.stage(100, || ring.pop_front()), 0);
        let first = stage.pop().unwrap();
        let rest = stage.take();
        let mut all = vec![first];
        all.extend(rest);
        assert_eq!(
            stamps(&all),
            [
                Some(0),
                Some(1),
                Some(2),
                None,
                Some(3),
                Some(4),
                Some(5),
                Some(6),
                Some(7),
                Some(8),
                Some(9)
            ]
        );
        assert_eq!(stage.len(), 0);

        let mut ring: std::collections::VecDeque<_> =
            discovery_items(0, DiscoveryStage::CAPACITY as u64 + 5).into();
        assert_eq!(
            stage.stage(usize::MAX, || ring.pop_front()),
            DiscoveryStage::CAPACITY
        );
        assert_eq!(ring.len(), 5, "overflow waits in the ring, never dropped");
        assert_eq!(
            stage.stage(1, || ring.pop_front()),
            0,
            "a full FIFO stages nothing"
        );
    }
}
