//! SPDX-License-Identifier: GPL-3.0-or-later
//! Loading and attaching. One selected entry uprobe + one uretprobe serve
//! each slot; the attach cookie carries the slot index.

use crate::discovery::hooks::HookAbi;
use crate::discovery::identity::{PinnedObjectId, PinnedObjects};
use crate::discovery::loader::LoaderContextId;
use crate::events;
use crate::plan::{AttachPlan, ObjectSlotEligibility, Slot};
use crate::run::OwnedChild;
use anyhow::{Context as _, Result, anyhow, bail};
use aya::maps::{Array, HashMap, Map, MapError, MapType, PerCpuArray, ProgramArray};
use aya::programs::raw_trace_point::RawTracePointLinkId;
use aya::programs::tp_btf::BtfTracePointLinkId;
use aya::programs::uprobe::{UProbeAttachLocation, UProbeAttachPoint, UProbeLinkId, UProbeScope};
use aya::programs::{BtfTracePoint, RawTracePoint, UProbe};
use aya::{Btf, Ebpf, EbpfLoader};
use p11scope_bpf_multi::{GroupHalt, attach_group, bisect_attach};
use p11scope_ebpf_common::object_wire::{ObjectDescriptorWire, publish_object_descriptors};
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

pub(crate) mod reexec_diagnostic;
#[cfg(feature = "h6-reexec-diagnostic")]
use reexec_diagnostic::{Outcome as DiagnosticOutcome, Phase as DiagnosticPhase};
use std::fs::File;
use std::io;
use std::mem::size_of_val;
use std::num::{NonZeroU32, NonZeroU64};
use std::os::fd::{AsFd as _, AsRawFd as _, BorrowedFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::OnceLock;
#[cfg(test)]
use std::sync::atomic::{AtomicU64, Ordering};

#[allow(dead_code)] // Unselected Counts bank transaction; no public loader/selector.
pub(crate) mod counter_banks;
mod counter_generation;
pub(crate) mod detailed_identity;
mod ended_pid_retirement;
mod global_retirement;
#[allow(dead_code)] // Collected carrier is staged before its coordinator activation.
mod native_retirement;
mod object_stop;
#[cfg(test)]
pub(crate) use native_retirement::fixture::RetirementFixture;
#[allow(unused_imports)] // Shared crate-private ports consumed by the next Engine packet.
pub(crate) use native_retirement::{
    CollectedGroupDeferral, CollectedRetirementState, CollectedRetirementTicket, DeferralProgress,
    RetainedInputMeasure, RetainedRetirementInput, RetainedRetirementInputRefusal,
    RetirementProgress,
};
pub(crate) use native_retirement::{RetirementPoll, RetirementTicket};
#[allow(dead_code)] // B2 records private facts; B3 supplies request-bound validation.
mod pid_continuity;
pub(crate) use ended_pid_retirement::EndedPidRetirement;
#[cfg(test)]
pub(crate) use pid_continuity::clock_origins_comparable_with;
#[cfg(test)]
pub(crate) use pid_continuity::engine_fixture::{
    AttachmentBoundaryChange, PidSessionFixture, PreflightChange,
};
pub(crate) use pid_continuity::{
    CompletedRearmReceipt, ExecBinding, PhysicalGapSummary, PidContinuityRefusal, PidLifecycleTap,
    PreservationReceipt, clock_origins_comparable,
};

// I3 will consume this preparation capability; I2b installs no callers or links.
#[allow(dead_code)]
mod inventory;
pub(crate) use inventory::EXPECTED_INVENTORY_DISCOVERY_BYTES;
#[allow(unused_imports)]
pub(crate) use inventory::PreparedInventory;
pub(crate) use inventory::capture;
#[allow(dead_code)] // Closed preparation; activation CAS is native, its promotion proof is joint.
pub(crate) mod selected_detailed;
mod stop_gate;
pub(crate) use stop_gate::{StopGate, stop_gate_map_data, validate_stop_gate};
// Task 3 Stage A: the readers are consumed by the Task 6 native seam
// (`stage_native`, DR-T3A-1) and today by the privileged instance gates.
pub(crate) mod host_btf;
#[allow(dead_code)]
pub(crate) mod image_query;
#[allow(dead_code)]
mod instance;
#[cfg(test)]
pub(crate) fn raise_fault_test_cell(cell: &std::sync::atomic::AtomicU64) -> Result<u64> {
    instance::raise_fault_cell(cell)
}
#[cfg(test)]
pub(crate) fn semantic_receipt_readback_test(
    policy: CapturePolicy,
    descriptors: Result<Vec<SlotSemantics>>,
) -> std::result::Result<(), crate::semantic_capture::CurrentReceiptRefusal> {
    semantic_receipt_readback(policy, descriptors)
}
#[cfg(test)]
pub(crate) fn semantic_receipt_query_refusal_test(
    error: image_query::ImageQueryRefusal,
) -> crate::semantic_capture::CurrentReceiptRefusal {
    semantic_receipt_query_refusal(error)
}
#[cfg(test)]
pub(crate) use instance::{AbsenceBirthSource, observe_absence_birth};
#[allow(unused_imports)]
pub(crate) use instance::{
    BirthAdmissionBinding, BirthObservationRefusal, BirthRowError, BirthRowReader, ExecBirthSource,
    HookStats, INSTANCE_PROGRAMS, InstanceMaps, InstanceTracking, LiveBirthRows, SessionGrantToken,
    WatchedFile, observe_exec_birth, observe_retained_birth,
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
#[path = "attach/joint_cells_native_tests.rs"]
mod joint_cells;
#[cfg(test)]
mod lifecycle_tests;
#[cfg(test)]
mod native_completion_tests;

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

const BASE_POLICY_MAPS: [(&str, ExactMapMetadata); 10] = [
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
    // H7 slice B subordinate custody: the loader-published frozen object
    // descriptor table (multi-entry read-only array: freezing defers past
    // load like DESCRIPTORS) and the verified zero template (frozen with
    // the published maps before any program loads).
    (
        "OBJECT_DESCRIPTORS",
        map_metadata(MapType::Array, 4, 16, MAX_DESCRIPTORS, BPF_F_RDONLY_PROG),
    ),
    (
        "OBJECT_ZERO",
        map_metadata(MapType::Array, 4, 432, 1, BPF_F_RDONLY_PROG),
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
        // Detailed includes H8's two retained journal words. Inventory's
        // separate objects intentionally keep the 544-byte base owner.
        map_metadata(MapType::TaskStorage, 4, 560, 0, 1),
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

fn owner_limit_from_start(ebpf: &Ebpf) -> Result<u64> {
    let map = ebpf.map("START").context("START map")?;
    let Map::HashMap(data) = map else {
        bail!("unexpected START map variant");
    };
    owner_limit_for_start(read_map_metadata("START", data)?)
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
        limit: owner_limit_from_start(ebpf)?,
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
    freeze_map_data(name, data)
}

/// Issue the freeze only after the owning object's exact map contract was
/// checked. Inventory and Detailed have distinct THREAD_OWNER value layouts.
fn freeze_map_data(name: &str, data: &aya::maps::MapData) -> Result<()> {
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
    native_selection: Option<selected_detailed::NativeSelection>,
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
    /// Reserved once before BPF preparation, in process-local allocation order.
    /// Collection identity only; this grants no capture or lifetime authority.
    counter_collection_generation: NonZeroU64,
    successful_static: BTreeSet<StaticEndpoint>,
    dynamic_attach_evidence: DynamicAttachEvidence,
    policy: CapturePolicy,
    /// The embedded flavor this session was set up with, checked at the
    /// gate before anything loaded. Grouping and output evidence read
    /// this, never a re-read of the global cache.
    embedded_flavor: EmbeddedFlavor,
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
    pid_pairs: pid_continuity::PairBook,
    global_retirements: global_retirement::Retirements,
    native_retirement: native_retirement::NativeRetirement,
    /// Removed members of partially covered shared-Multi groups. Their
    /// links stay in `links` until the terminal detach closes them; every
    /// selective mutation guard refuses while this is nonempty, and the
    /// native mint requires these slots proven terminally submitted.
    deferred_group_slots: BTreeSet<u32>,
    /// Slots of the links the terminal detach actually submitted. The
    /// mint proves `deferred_group_slots` against this set.
    submitted_terminal_slots: BTreeSet<u32>,
    pid_health: pid_continuity::OwnerHealth,
    prepared_owner_limit: u64,
    pid_lifecycle: Option<PidLifecycleTap>,
    links: Vec<RegisteredLink>,
    /// Task 3 Stage A continuity witness: hook links, watched files and the
    /// refusal reason when instance routing is unavailable.
    instance: InstanceTracking,
    /// Background link cleanup, pre-started during preparation so the
    /// worker thread exists before any submit. `None` once a detach has
    /// driven it to completion; a fresh worker is created if links ever
    /// need closing afterwards.
    cleanup_worker: Option<CleanupWorker>,
    /// Terminal transfer and settlement belong to this exact Session. An
    /// interrupted/failed drive can never infer success from empty links.
    producer_detach: OwnedProducerDetach,
    /// Sticky native-completion mint refusal: set once a mint attempt
    /// fails after its terminal poll consumed records, after which the
    /// Session can never mint (see [`NativeCompletionMint`]).
    native_completion_mint: NativeCompletionMint,
    /// H7 slice D: receipt-bound object rows for 608-byte decode, frozen
    /// by `Session::start_attested` only. `None` everywhere else keeps
    /// those lanes 368-byte-only.
    object_decode: Option<ObjectDecodeTable>,
    #[cfg(feature = "h6-reexec-diagnostic")]
    reexec_diagnostic: Option<reexec_diagnostic::Diagnostic>,
    /// Last: synchronous Aya links/maps/pins drop before the reservation.
    /// Every asynchronous transferred link also carries the same keepalive.
    counter_banks: Option<counter_banks::CounterBanks>,
}

/// Move-only terminal work, stored inside its original Session. Submission is
/// not settlement; only the joined worker receipt can reach Complete.
#[derive(Default)]
enum OwnedProducerDetach {
    #[default]
    NotStarted,
    Pending {
        worker: CleanupWorker,
        started: std::time::Instant,
        had_work: bool,
        progress: cleanup_worker::DetachPollPrinter,
    },
    Unproved,
    Complete,
}

/// Non-consuming reap progress: `Pending` keeps the SAME worker thread
/// and every original lease in place; only a joined receipt reaches
/// `Complete`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProducerDetachProgress {
    Pending,
    Complete,
}

impl OwnedProducerDetach {
    fn started(&self) -> bool {
        !matches!(self, Self::NotStarted)
    }

    /// Snapshot-only readiness. Attempted is not settled: only returned
    /// closes count, and this never moves a worker. Production reaps
    /// through `poll`; only tests still snapshot readiness.
    #[cfg(test)]
    fn ready_to_finish(&self) -> bool {
        match self {
            Self::Pending { worker, .. } => {
                let progress = worker.progress();
                !worker.running()
                    || progress
                        .released
                        .checked_add(progress.uncertain)
                        .is_some_and(|settled| settled >= progress.total)
            }
            Self::Complete => true,
            Self::NotStarted | Self::Unproved => false,
        }
    }

    fn drive(
        &mut self,
        failures: &mut Vec<String>,
        detached: &mut bool,
        wall_ms: &mut u64,
        second_signal: impl Fn() -> bool,
        out: &mut dyn std::io::Write,
    ) -> Result<()> {
        let prior = std::mem::replace(self, Self::Unproved);
        let Self::Pending {
            worker,
            started,
            had_work,
            ..
        } = prior
        else {
            if matches!(prior, Self::Complete) {
                *self = Self::Complete;
                return finish_producer_detach(detached, failures, Ok(()));
            }
            *detached = false;
            bail!("producer detach has no unsettled owned job; completion remains unproven");
        };
        // Empty workers still join honestly, without adding an empty-cleanup
        // notice to captures which owned no native producers.
        let mut quiet = std::io::sink();
        let output: &mut dyn std::io::Write = if had_work { out } else { &mut quiet };
        let exit = drive_cleanup(
            worker,
            second_signal,
            output,
            std::time::Duration::from_secs(1),
        );
        *wall_ms = record_detach_wall_ms(*wall_ms, had_work, detach_wall_ms_since(started));
        let complete =
            matches!(&exit, cleanup_worker::CleanupExit::Completed(receipt) if receipt.completed);
        let result = match cleanup_worker::settle_cleanup_exit(exit) {
            Ok(joined_failures) => {
                failures.extend(joined_failures);
                if !complete && failures.is_empty() {
                    failures
                        .push("joined producer cleanup did not prove complete settlement".into());
                }
                Ok(())
            }
            Err(interrupted) => Err(interrupted.into()),
        };
        let result = finish_producer_detach(detached, failures, result);
        if result.is_ok() {
            *self = Self::Complete;
        }
        result
    }

    /// Non-consuming reap: while the worker thread is still closing,
    /// `try_join` reports pending and the SAME worker stays in place
    /// with every original lease. Only a joined receipt settles, through
    /// the same `settle_cleanup_exit` + `finish_producer_detach` path as
    /// `drive`. Pending polls print the one-shot estimate and the ~1/s
    /// progress line through `out`, same text as the blocking `drive`.
    fn poll(
        &mut self,
        failures: &mut Vec<String>,
        detached: &mut bool,
        wall_ms: &mut u64,
        out: &mut dyn std::io::Write,
    ) -> Result<ProducerDetachProgress> {
        let Self::Pending {
            worker,
            started,
            had_work,
            progress,
        } = self
        else {
            if matches!(self, Self::Complete) {
                finish_producer_detach(detached, failures, Ok(()))?;
                return Ok(ProducerDetachProgress::Complete);
            }
            if matches!(self, Self::NotStarted) {
                bail!("owned producer detach not begun");
            }
            *detached = false;
            bail!("producer detach has no unsettled owned job; completion remains unproven")
        };
        let started = *started;
        let had_work = *had_work;
        let Some(receipt) = worker.try_join() else {
            progress.poll_pending(worker, had_work, out);
            return Ok(ProducerDetachProgress::Pending);
        };
        *wall_ms = record_detach_wall_ms(*wall_ms, had_work, detach_wall_ms_since(started));
        let complete = receipt.completed;
        let result = match cleanup_worker::settle_cleanup_exit(
            cleanup_worker::CleanupExit::Completed(receipt),
        ) {
            Ok(joined_failures) => {
                failures.extend(joined_failures);
                if !complete && failures.is_empty() {
                    failures
                        .push("joined producer cleanup did not prove complete settlement".into());
                }
                Ok(())
            }
            Err(interrupted) => Err(interrupted.into()),
        };
        let result = finish_producer_detach(detached, failures, result);
        if result.is_ok() {
            *self = Self::Complete;
        } else {
            *self = Self::Unproved;
        }
        result?;
        Ok(ProducerDetachProgress::Complete)
    }
}

/// Substituted native I/O drives the same terminal state/receipt consumer.
#[cfg(test)]
pub(crate) fn drive_owned_producer_detach_for_test(
    worker: CleanupWorker,
    second_signal: &dyn Fn() -> bool,
    out: &mut dyn std::io::Write,
) -> Result<()> {
    let had_work = worker.has_submissions();
    let mut job = OwnedProducerDetach::Pending {
        worker,
        started: std::time::Instant::now(),
        had_work,
        progress: cleanup_worker::DetachPollPrinter::new(),
    };
    job.drive(&mut Vec::new(), &mut false, &mut 0, second_signal, out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TerminalProducerFamily {
    Registered,
    InstanceHooks,
}

/// The terminal submission boundary over the Session's original owner
/// registries. Tests replace native take I/O while using its actual worker.
fn submit_terminal_ownership(
    worker: &CleanupWorker,
    leases: cleanup_worker::FileLeases,
    mut take: impl FnMut(TerminalProducerFamily) -> Vec<Result<(OwnedLink, ProducerProgram)>>,
) -> Vec<String> {
    let mut owned = Vec::new();
    let mut failures = Vec::new();
    for family in [
        TerminalProducerFamily::Registered,
        TerminalProducerFamily::InstanceHooks,
    ] {
        for outcome in take(family) {
            match outcome {
                Ok(link) => owned.push(link),
                Err(error) => failures.push(format!("{error:#}")),
            }
        }
    }
    worker.note_transfer_failed(failures.len());
    worker.submit(owned, leases, DetachOrder);
    failures
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

/// Refuse fresh attachment once the Session is stopping or detached: a
/// post-terminal link would silently extend capture past the joined
/// detach a saved completion attests. Refusal (never silent invalidation)
/// is the codebase semantic — static attach inlines the same check, the
/// group rebuild re-checks it after its baseline read, and a new Session
/// is the recovery. Every path that adds a link past static attach
/// funnels through here before touching BPF; idempotent no-ops
/// (already-attached dedup) still succeed.
fn stopped_attachment_admission(mutation_stopped: bool, path: &str) -> Result<()> {
    if mutation_stopped {
        bail!("{path} attachment refused while Session is stopping or detached");
    }
    Ok(())
}

fn static_attachment_baseline_with<S>(
    state: &mut S,
    acquire: impl FnOnce(&mut S) -> Option<pid_continuity::AttachBaseline>,
    mutation_stopped: impl FnOnce(&S) -> bool,
) -> Result<Option<pid_continuity::AttachBaseline>> {
    let baseline = acquire(state);
    // The fresh read may have latched terminal poison after the caller's
    // earlier admission. Healthy unavailable proof still permits cold/global
    // attachment; explicit stop, terminal or detach state never does.
    if mutation_stopped(state) {
        bail!("static attachment refused while Session is stopping or detached");
    }
    Ok(baseline)
}

fn refused_group_rebuild(
    members: impl IntoIterator<Item = u32>,
    rebuilt_groups: u64,
    reason: &str,
) -> DetachOutcome {
    DetachOutcome {
        pending: None,
        recompleted: Vec::new(),
        rebuild_failures: members
            .into_iter()
            .map(|member| {
                (
                    member,
                    format!("slot {member} was not reattached: {reason}"),
                )
            })
            .collect(),
        rebuilt_groups,
    }
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
    InstanceHook(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ProbeSide {
    Return,
    Entry,
}

pub(crate) type StaticEndpoint = (u32, ProbeSide);

fn current_static_sides_from(links: &[RegisteredLink]) -> BTreeSet<StaticEndpoint> {
    links
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

/// One link whose lifetime this session owns. Static, loader/export, and
/// lifecycle links all remain in this one registry.
enum RegisteredLink {
    UProbe {
        program: &'static str,
        slot: u32,
        id: UProbeLinkId,
        registration: Option<pid_continuity::RegistrationId>,
    },
    /// One attached multi group side outside Aya's link table: the
    /// program, its member slots, and the live link fds (one per bisect
    /// leaf). Detach is drop: closing the fds detaches the links.
    MultiUProbe {
        program: &'static str,
        slots: Vec<u32>,
        fds: Vec<OwnedFd>,
        registration: Option<pid_continuity::RegistrationId>,
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
/// True when every deferred group slot was terminally submitted.
/// The mint proves the deferred set against the submitted set; an empty
/// deferral proves vacuously.
fn deferred_slots_proven(deferred: &BTreeSet<u32>, submitted: &BTreeSet<u32>) -> bool {
    deferred.iter().all(|slot| submitted.contains(slot))
}

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
        ProducerProgram::UProbe("p11_entry" | "p11_counter_bank_entry") => 0,
        ProducerProgram::UProbe("p11_entry_ia32") => 1,
        ProducerProgram::UProbe("p11_entry_template") => 2,
        ProducerProgram::UProbe("p11_entry_template_types") => 3,
        ProducerProgram::UProbe("p11_entry_template_pair") => 4,
        ProducerProgram::BtfTracePoint("task_newtask") => 5,
        ProducerProgram::UProbe("p11_return" | "p11_counter_bank_return") => 6,
        ProducerProgram::RawTracePoint(_) => 8,
        ProducerProgram::InstanceHook(_) => 9,
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
pub(crate) struct AttachOutcome {
    successful: BTreeSet<StaticEndpoint>,
    failures: Vec<(u32, String)>,
    completed: Vec<SlotCompletion>,
    continuity_rounds: Vec<pid_continuity::AttachRound>,
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
    /// Only the ordinary global candidate consumer may defer publication.
    pub(crate) pending: Option<RetirementTicket>,
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
        "p11_return" | "p11_counter_bank_return" => Some(ProbeSide::Return),
        "p11_entry"
        | "p11_entry_ia32"
        | "p11_entry_template"
        | "p11_entry_template_types"
        | "p11_entry_template_pair"
        | "p11_counter_bank_entry" => Some(ProbeSide::Entry),
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
    return_program: &'static str,
    members: Vec<StaticGroupMember>,
}

/// One statically attached slot's exact reattach facts: the descriptor the
/// attach used plus the pinned path/ABI it resolved. Retained so a
/// multi-group rebuild can reattach surviving siblings without re-deriving
/// identity; facts survive exactly while a link does.
#[derive(Debug)]
pub(crate) struct RetainedStaticTarget {
    slot: Slot,
    path: PathBuf,
    abi: ElfAbi,
    held: Option<crate::discovery::identity::RetainedInventoryTarget>,
}

impl Clone for RetainedStaticTarget {
    fn clone(&self) -> Self {
        Self {
            slot: self.slot.clone(),
            path: self.path.clone(),
            abi: self.abi,
            held: self.held.as_ref().map(|target| target.share()),
        }
    }
}

impl RetainedStaticTarget {
    fn retirement_lease(&self) -> Option<Arc<std::fs::File>> {
        self.held.as_ref().map(|target| target.retirement_lease())
    }
}

/// Test-only interim attachment generation: every successful test
/// sealing mints the next value, so the closure generation the
/// journal observes always names a real sealed endpoint set. Fenced
/// from production (which mints from the mmapable attach cell): the
/// interim counter alone never feeds production authority.
#[cfg(test)]
static ATTACHMENT_GENERATION: AtomicU64 = AtomicU64::new(0);

/// Session-owned attachment authority. Fields and constructor stay private.
pub(crate) struct AttachedSemanticSet {
    domain: crate::attach::capture::NativeDomainId,
    subset: crate::inventory_semantics::AttestedSubset,
    generation: u64,
}

impl std::fmt::Debug for AttachedSemanticSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AttachedSemanticSet(<retained>)")
    }
}

impl AttachedSemanticSet {
    /// The native identity domain this attachment was sealed under.
    pub(crate) fn domain(&self) -> crate::attach::capture::NativeDomainId {
        self.domain
    }

    /// The attachment's sealing generation: minted only by a
    /// successful sealing, observed (never supplied) by the journal's
    /// closure install, grant and audit.
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
}

/// One Session's retained drain producers: its native identity
/// domain plus its retained EVENTS domain. Private fields:
/// production builds one only through [`Session::drain_producers`]
/// (which retains both); the drain grant mints through the pair, so
/// a spliced foreign admission refuses at mint instead of pairing.
#[derive(Clone)]
pub(crate) struct SessionDrainProducers {
    native: crate::attach::capture::NativeDomainId,
    events: events::EventsDomain,
}

/// Session-owned Q metadata. No constructor, Clone or Copy permits a caller
/// to manufacture quiescence from ring positions or a terminal summary.
/// This records producer bounds, not a clean prefix, completed drain, process
/// death, or permission to detach. Later reads must remain within the bounds.
pub(crate) struct CollectedFinishQ {
    producers: SessionDrainProducers,
    discovery: events::DiscoveryDomain,
    events: events::EventsConsumptionCut,
    discovery_positions: aya::maps::ring_buf::RingBufPositions,
    grant: Option<crate::semantics_objects::journal::SessionDrainGrant>,
}

#[cfg_attr(not(test), allow(dead_code))] // Staged Q API; no machine/terminal consumer is active.
impl CollectedFinishQ {
    pub(crate) fn matches_owner(
        &self,
        producers: &SessionDrainProducers,
        discovery: &events::DiscoveryDomain,
    ) -> bool {
        self.producers.same_producers(producers) && self.discovery.same_allocation(discovery)
    }

    #[cfg(test)]
    pub(crate) fn matches_discovery_drain<S: events::RecordSource>(
        &self,
        producers: &SessionDrainProducers,
        drain: &events::DiscoveryDrain<S>,
    ) -> bool {
        self.producers.same_producers(producers) && drain.same_domain(&self.discovery)
    }

    pub(crate) fn matches_retained_grant(
        &self,
        grant: &crate::semantics_objects::journal::SessionDrainGrant,
    ) -> bool {
        self.grant.as_ref().is_some_and(|retained| {
            retained == grant && retained.matches_producers(&self.producers)
        })
    }

    /// Observation metadata only: Q does not acquire a later admission grant.
    pub(crate) fn observed_without_grant(&self) -> bool {
        self.grant.is_none()
    }

    pub(crate) fn events_stop(&self) -> usize {
        self.events.producer_bound()
    }

    pub(crate) fn discovery_stop(&self) -> usize {
        self.discovery_positions.producer
    }

    pub(crate) fn covers_events_bounds(&self, cut: &events::EventsConsumptionCut) -> bool {
        cut.within_producer_bound(&self.events)
    }

    pub(crate) fn events_at_bound(&self, cut: &events::EventsConsumptionCut) -> bool {
        cut.at_producer_bound(&self.events)
    }
}

/// Private borrowed view. Production supplies only the owning Session's
/// retained fields; tests substitute the native read leaves beneath it.
struct CollectedFinishQOwner<'a> {
    gate: &'a StopGate,
    producers: &'a SessionDrainProducers,
    discovery: &'a events::DiscoveryDomain,
    detach: &'a OwnedProducerDetach,
}

fn validate_collected_finish_q_owner(
    owner: &CollectedFinishQOwner<'_>,
    expected: &SessionDrainProducers,
    grant: Option<&crate::semantics_objects::journal::SessionDrainGrant>,
) -> Result<()> {
    anyhow::ensure!(
        owner.producers.same_producers(expected),
        "collected Finish Q requires the original Session producers"
    );
    anyhow::ensure!(
        matches!(owner.detach, OwnedProducerDetach::NotStarted),
        "collected Finish Q cannot follow producer detach"
    );
    anyhow::ensure!(
        grant.is_none_or(|retained| retained.matches_producers(owner.producers)),
        "collected Finish Q refuses a foreign retained drain grant"
    );
    Ok(())
}

fn observe_collected_finish_q_with(
    owner: CollectedFinishQOwner<'_>,
    expected: &SessionDrainProducers,
    grant: Option<&crate::semantics_objects::journal::SessionDrainGrant>,
    read_events: impl FnOnce() -> Result<events::EventsConsumptionCut>,
    read_discovery: impl FnOnce() -> Result<aya::maps::ring_buf::RingBufPositions>,
) -> Result<Option<CollectedFinishQ>> {
    validate_collected_finish_q_owner(&owner, expected, grant)?;
    if !owner.gate.quiescent() {
        return Ok(None);
    }
    let events = read_events()?;
    anyhow::ensure!(
        owner.producers.matches_events(events.events()),
        "collected Finish Q refuses another EVENTS allocation"
    );
    let discovery_positions = read_discovery()?;
    anyhow::ensure!(
        discovery_positions.consumer.is_multiple_of(8)
            && discovery_positions.producer.is_multiple_of(8)
            && discovery_positions.capacity != 0
            && discovery_positions.capacity.is_power_of_two()
            && discovery_positions.consumer != usize::MAX
            && discovery_positions.producer != usize::MAX
            && discovery_positions
                .producer
                .checked_sub(discovery_positions.consumer)
                .is_some_and(|unread| unread <= discovery_positions.capacity),
        "collected Finish Q refuses invalid DISCOVERY positions"
    );
    // Q must still hold after BOTH original ring observations. No dequeue,
    // callback, OBJECT_START scrub or lifecycle proof occurs in this observer.
    if !owner.gate.quiescent() {
        return Ok(None);
    }
    Ok(Some(CollectedFinishQ {
        producers: owner.producers.clone(),
        discovery: owner.discovery.clone(),
        events,
        discovery_positions,
        grant: grant.copied(),
    }))
}

impl SessionDrainProducers {
    pub(crate) fn same_producers(&self, other: &Self) -> bool {
        self.native == other.native && self.events.same_allocation(&other.events)
    }

    pub(crate) fn matches_events(&self, events: &events::EventsDomain) -> bool {
        self.events.same_allocation(events)
    }

    /// The retained native domain the admission is checked against.
    pub(crate) fn native_domain(&self) -> crate::attach::capture::NativeDomainId {
        self.native
    }

    /// The retained EVENTS-map identity the grant binds.
    pub(crate) fn events_id(&self) -> u64 {
        self.events.id()
    }

    /// Pair one scene's genuine test producers: its fixture's minted
    /// native domain plus its retained test EVENTS domain. The
    /// common-owner check still runs at mint — this pairs values, it
    /// never authorizes a splice.
    #[cfg(test)]
    pub(crate) fn test_pair(
        native: crate::attach::capture::NativeDomainId,
        events: events::EventsDomain,
    ) -> Self {
        Self { native, events }
    }
}

/// Native-owned terminal completion: the joined proof that a Session's
/// terminal sequence actually ran — joined producer detach, proven Q, a
/// backlog-free bounded terminal EVENTS drain and a completed
/// OBJECT_START scrub. Only [`Session::mint_native_completion`] mints one
/// (tests adjudicate explicit evidence through `from_joined_evidence`);
/// there is no other constructor, so joint lanes consume but never
/// manufacture it.
///
/// Single-session consumption contract: the completion binds the
/// minting Session's retained EVENTS identity (`events_id`), not just
/// counts, so a well-formed completion from another session is
/// recognizable as foreign. The DR37 1C/1F joint promotion wiring must,
/// at consumption: (1) consume each completion at most once for its
/// minting Session; (2) refuse when
/// `!completion.binds_events(&session.events_domain())` — a foreign
/// session's completion never promotes here; (3) never persist or replay
/// a completion past its Session's lifetime — the retained FD pins the
/// kernel map ID against reuse only while that history survives, and
/// only within that lifetime is the binding meaningful.
#[allow(dead_code)] // The completion minter consumes the mint; per-field evidence reads stay test-pinned.
#[derive(Debug)]
pub(crate) struct SessionNativeCompletion {
    terminal_events: u64,
    terminal_malformed: u64,
    scrubbed_objects: usize,
    detach_wall_ms: u64,
    selected_terminal: bool,
    events_id: u64,
}

#[allow(dead_code)] // The completion minter consumes the mint; the evidence getters stay test-pinned.
impl SessionNativeCompletion {
    /// The join gates both ends of the mint enforce: the fail-fast at the
    /// top of [`Session::mint_native_completion`] (before the terminal
    /// poll, so a refused mint consumes nothing and no retry can mint
    /// over a split backlog) and the end adjudication here (defense in
    /// depth with the post-poll Q re-check). One shared check, so the two
    /// can never drift.
    fn join_gates(detach_complete: bool, quiescent: bool) -> Result<()> {
        anyhow::ensure!(
            detach_complete,
            "native completion requires joined producer detach"
        );
        anyhow::ensure!(quiescent, "native completion requires proven quiescence");
        Ok(())
    }

    /// Adjudicate observed native evidence into a completion. Every gate
    /// must hold: joined detach, proven quiescence, no terminal-drain
    /// backlog, no reserved-but-uncommitted EVENTS head. Counts ride along
    /// untouched; an empty scrub (nothing retained) or an ordinary session
    /// (no selection) still mints, since the completed scrub and the
    /// joined detach are the proof, not the counts. `events_id` is the
    /// minting Session's retained EVENTS identity the joint promotion
    /// lane re-checks at consumption (see the struct contract).
    /// (Too many arguments is the honest shape: every gate is injected,
    /// none supplied.)
    #[allow(clippy::too_many_arguments)]
    fn from_joined_evidence(
        detach_complete: bool,
        quiescent: bool,
        backlog: bool,
        head_pending: bool,
        terminal_events: u64,
        terminal_malformed: u64,
        scrubbed_objects: usize,
        detach_wall_ms: u64,
        selected_terminal: bool,
        events_id: u64,
    ) -> Result<Self> {
        Self::join_gates(detach_complete, quiescent)?;
        Self::refuse_drain_verdict(backlog, head_pending)?;
        Ok(Self {
            terminal_events,
            terminal_malformed,
            scrubbed_objects,
            detach_wall_ms,
            selected_terminal,
            events_id,
        })
    }

    /// EVENTS records the mint's own bounded terminal poll consumed:
    /// post-semantic-drain leftovers and post-Q arrivals, never the
    /// semantic lane's routed batches.
    pub(crate) fn terminal_events(&self) -> u64 {
        self.terminal_events
    }

    /// Malformed records met by the mint's own terminal poll.
    pub(crate) fn terminal_malformed(&self) -> u64 {
        self.terminal_malformed
    }

    /// OBJECT_START rows the mint's scrub zeroed and removed.
    pub(crate) fn scrubbed_objects(&self) -> usize {
        self.scrubbed_objects
    }

    /// Wall time the joined producer detach took, in whole milliseconds.
    pub(crate) fn detach_wall_ms(&self) -> u64 {
        self.detach_wall_ms
    }

    /// True only when a native selection existed and read back TERMINAL
    /// at mint. Ordinary sessions mint with false.
    pub(crate) fn selected_terminal(&self) -> bool {
        self.selected_terminal
    }

    /// The minting Session's retained EVENTS identity.
    pub(crate) fn events_id(&self) -> u64 {
        self.events_id
    }

    /// True only for the retained EVENTS domain this completion was minted
    /// from. The joint promotion lane checks this at consumption: a
    /// completion never promotes a foreign session (see the struct
    /// contract).
    pub(crate) fn binds_events(&self, domain: &events::EventsDomain) -> bool {
        self.events_id == domain.id()
    }

    /// Refuse a terminal poll verdict that already proves the mint
    /// cannot join: backlog past the bound, or a reserved-but-
    /// uncommitted EVENTS head. The pre-scrub fail-fast in
    /// [`Session::mint_native_completion`] and the end adjudication in
    /// `from_joined_evidence` share this one check, so the two can never
    /// drift — and a known-bad verdict refuses before the scrub, whose
    /// error can therefore neither run on doomed evidence nor preempt
    /// the by-name diagnostic.
    fn refuse_drain_verdict(backlog: bool, head_pending: bool) -> Result<()> {
        anyhow::ensure!(
            !backlog,
            "native completion refused: terminal drain left backlog past its bound"
        );
        anyhow::ensure!(
            !head_pending,
            "native completion refused: EVENTS head reserved but uncommitted"
        );
        Ok(())
    }
}

/// Sticky refusal for the native completion mint: once an attempt fails
/// after its terminal poll consumed records, the Session can never mint
/// again — a retry would drain only the leftover tail and mint over the
/// consumed prefix the refusal ate (65,537 queued: attempt 1 eats 65,536
/// and refuses for backlog; attempt 2 would mint terminal_events=1 over
/// the forgotten attempt 1). Pre-consumption refusals — the admission
/// and join gates, the selected gate, consumer setup — ate nothing and
/// leave the mint admissible.
#[derive(Default)]
struct NativeCompletionMint {
    failed_after_consumption: bool,
}

impl NativeCompletionMint {
    /// Fail-fast admission at the top of the mint, before the terminal
    /// poll: a Session poisoned by a destructive mint failure refuses
    /// without consuming anything further.
    fn admit(&self) -> Result<()> {
        anyhow::ensure!(
            !self.failed_after_consumption,
            "native completion refused: a prior mint attempt failed after consuming terminal evidence"
        );
        Ok(())
    }

    /// Record a failure after the terminal poll consumed: the mint is
    /// terminally refused for this Session.
    fn record_destructive_failure(&mut self) {
        self.failed_after_consumption = true;
    }
}

/// Bound on the completion minter's preserved first mint failure:
/// generous over one-line mint refusals, and the gap path reports
/// each preserved failure exactly once.
pub(crate) const COMPLETION_FIRST_FAILURE_MAX: usize = 512;

/// The production native completion minter (DR37 D4/A→B): owns
/// wound-down Sessions and mints one lifecycle completion per
/// genuinely disposed domain. Each poll attempts the held Session's
/// own terminal proof (joined detach, proven quiescence,
/// backlog-free terminal drain, object-start scrub); unmet gates
/// poll `None` and the namespace holds, never forced. A minted
/// Session is spent (its terminal evidence consumed) and drops with
/// its maps; a domain/Session pairing that disagrees drops closed
/// instead of retiring the wrong namespace. A failed mint polls
/// `None` too, but its cause is preserved (first failure, bounded)
/// for the driver's diagnostic take instead of vanishing.
#[derive(Default)]
pub(crate) struct NativeCompletionMinter {
    pending: std::collections::HashMap<capture::NativeDomainId, Session>,
    first_failure: Option<String>,
}

impl NativeCompletionMinter {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Preserve a mint failure for the diagnostic take: first one
    /// wins, truncated to [`COMPLETION_FIRST_FAILURE_MAX`] on a
    /// character boundary. Later failures never displace it, so the
    /// reported cause is always the original refusal.
    fn record_first_failure(&mut self, mut failure: String) {
        if self.first_failure.is_some() {
            return;
        }
        if failure.len() > COMPLETION_FIRST_FAILURE_MAX {
            let mut end = COMPLETION_FIRST_FAILURE_MAX;
            while !failure.is_char_boundary(end) {
                end -= 1;
            }
            failure.truncate(end);
        }
        self.first_failure = Some(failure);
    }
}

impl crate::inventory_promotion::lifecycle::NativeCompletionSource for NativeCompletionMinter {
    fn poll_completion(
        &mut self,
        domain: capture::NativeDomainId,
    ) -> Option<crate::inventory_promotion::lifecycle::SessionNativeCompletion> {
        let session = self.pending.get_mut(&domain)?;
        if session.native_domain() != Some(domain) {
            // The driver mislabeled this pairing: drop the Session
            // closed rather than retire the wrong namespace. The
            // namespace holds, honestly unproven.
            self.pending.remove(&domain);
            return None;
        }
        if let Err(error) = session.mint_native_completion() {
            self.record_first_failure(format!("{error:#}"));
            return None;
        }
        self.pending.remove(&domain);
        Some(crate::inventory_promotion::lifecycle::SessionNativeCompletion::completed(domain))
    }

    fn note_wound_down(&mut self, domain: capture::NativeDomainId, session: Session) {
        self.pending.insert(domain, session);
    }

    fn take_first_failure(&mut self) -> Option<String> {
        self.first_failure.take()
    }
}

/// The completion mint's bounded terminal EVENTS poll over the retained
/// consumer: counts consumed records and the malformed delta, and reports
/// `backlog` when the poll stopped with records queued, plus a separate
/// `head_pending` when positions still show unread bytes after an empty
/// read (the head is reserved but uncommitted — the unbounded `poll` maps
/// that Pending head to `None`, so positions are the verdict, per
/// `events_head_pending`). Generic over the source so tests pin the exact
/// verdict the mint consumes.
struct TerminalPollVerdict {
    backlog: bool,
    head_pending: bool,
    terminal_events: u64,
    terminal_malformed: u64,
}

fn terminal_poll_verdict<S>(drain: &mut events::EventDrain<S>) -> TerminalPollVerdict
where
    S: events::RecordSource + events::BoundedRecordSource,
{
    let malformed_before = drain.malformed();
    let mut terminal_events = 0u64;
    let backlog = drain.poll(Some(events::TERMINAL_DRAIN_BOUND), |_| {
        terminal_events = terminal_events.saturating_add(1);
        std::ops::ControlFlow::Continue(())
    });
    TerminalPollVerdict {
        backlog,
        head_pending: events::events_head_pending(drain),
        terminal_events,
        terminal_malformed: drain.malformed().saturating_sub(malformed_before),
    }
}

/// Seal one operator-attested subset into Session-owned attachment
/// authority with a NATIVE mint: validates exactly like the test
/// sealer, then mints the generation from the mmapable attach cell
/// (BPF stamps exec'ing records from it as `exec_attach_gen`), so the
/// sealed generation always names a natively published endpoint set.
/// A failed native mint refuses the sealing. Production seals here;
/// the interim userspace counter never feeds production authority.
/// (Too many arguments is the honest shape: every seal input is
/// injected, none supplied.)
#[allow(clippy::too_many_arguments)]
pub(crate) fn seal_attached_subset_native(
    ebpf: &Ebpf,
    subset: crate::inventory_semantics::AttestedSubset,
    domain: crate::attach::capture::NativeDomainId,
    policy: CapturePolicy,
    descriptors: Result<Vec<SlotSemantics>>,
    retained: &BTreeMap<u32, RetainedStaticTarget>,
    owned_sides: &BTreeSet<StaticEndpoint>,
    watched: impl Fn(PinnedObjectId) -> Option<crate::discovery::identity::RetainedInventoryTarget>,
) -> std::result::Result<AttachedSemanticSet, crate::inventory_semantics::SemanticRefusal> {
    let mut attached = AttachedSemanticSet {
        domain,
        subset,
        generation: 0,
    };
    attached.validate_with(domain, policy, descriptors, retained, owned_sides, watched)?;
    // Only a successful sealing mints, from native: the generation
    // always names a complete validated endpoint set published to the
    // attach cell, never a refused one or a bare counter value.
    let maps = instance::InstanceMaps { ebpf };
    attached.generation = maps
        .mint_attach_generation()
        .map_err(|_| crate::inventory_semantics::SemanticRefusal::Attachment)?;
    Ok(attached)
}

/// Test-only seal over fixture-built maps through the same validation:
/// host tests seal their successful-attachment evidence here (and via
/// `seal_test_attachment`). Fenced from production, which seals
/// through `seal_attached_subset_native` with a native mint. The
/// sealed receipt is the successful-attachment evidence birth
/// observation requires.
#[cfg(test)]
pub(crate) fn seal_attached_subset_with(
    subset: crate::inventory_semantics::AttestedSubset,
    domain: crate::attach::capture::NativeDomainId,
    policy: CapturePolicy,
    descriptors: Result<Vec<SlotSemantics>>,
    retained: &BTreeMap<u32, RetainedStaticTarget>,
    owned_sides: &BTreeSet<StaticEndpoint>,
    watched: impl Fn(PinnedObjectId) -> Option<crate::discovery::identity::RetainedInventoryTarget>,
) -> std::result::Result<AttachedSemanticSet, crate::inventory_semantics::SemanticRefusal> {
    let mut attached = AttachedSemanticSet {
        domain,
        subset,
        generation: 0,
    };
    attached.validate_with(domain, policy, descriptors, retained, owned_sides, watched)?;
    // Only a successful sealing mints: the generation always names a
    // complete validated endpoint set, never a refused one.
    attached.generation = ATTACHMENT_GENERATION.fetch_add(1, Ordering::SeqCst);
    Ok(attached)
}

/// Test-only sealed attachment over a fixture subset: actual attach
/// scheduling and retention through the Session seams; only link I/O
/// is scripted. Birth observation tests seal their
/// successful-attachment evidence here.
#[cfg(test)]
pub(crate) fn seal_test_attachment(
    subset: crate::inventory_semantics::AttestedSubset,
    domain: crate::attach::capture::NativeDomainId,
    pins: &crate::discovery::identity::PinnedObjects,
) -> AttachedSemanticSet {
    let outcome = attach_targets_with(
        subset.plan().slots.as_slice(),
        CapturePolicy::Allowlisted,
        false,
        |slot| Ok(subset.pins().abi_for(slot.object).unwrap()),
        |_, _, _| Ok(()),
        |_| Some(1),
    )
    .unwrap();
    let targets = subset
        .plan()
        .slots
        .iter()
        .map(|slot| {
            (
                slot.index,
                (
                    subset.pins().attach_path_for(slot.object).unwrap(),
                    subset.pins().abi_for(slot.object).unwrap(),
                ),
            )
        })
        .collect();
    let mut retained = BTreeMap::new();
    retain_from_successful(
        &mut retained,
        &subset.plan().slots,
        &targets,
        &outcome.successful,
    );
    seal_attached_subset_with(
        subset,
        domain,
        CapturePolicy::Allowlisted,
        Ok(crate::kinds::DESCRIPTORS.to_vec()),
        &retained,
        &outcome.successful,
        |id| pins.retain_inventory_target(id).ok(),
    )
    .expect("fixture attachment seals")
}

/// Closure-change fixture: consume the SAME retained envelope, rerun the
/// normal successful test sealing/validate_with path, then mint its next
/// generation. No pathname reopen or bare generation setter is involved.
#[cfg(test)]
pub(crate) fn reseal_test_attachment(
    attached: AttachedSemanticSet,
    pins: &crate::discovery::identity::PinnedObjects,
) -> AttachedSemanticSet {
    let AttachedSemanticSet { domain, subset, .. } = attached;
    seal_test_attachment(subset, domain, pins)
}

fn semantic_receipt_readback(
    policy: CapturePolicy,
    descriptors: Result<Vec<SlotSemantics>>,
) -> std::result::Result<(), crate::semantic_capture::CurrentReceiptRefusal> {
    use crate::semantic_capture::CurrentReceiptRefusal as Refusal;
    if policy != CapturePolicy::Allowlisted
        || descriptors.map_err(|_| Refusal::Attachment)? != *crate::kinds::DESCRIPTORS
    {
        return Err(Refusal::Attachment);
    }
    Ok(())
}

fn semantic_receipt_query_refusal(
    error: image_query::ImageQueryRefusal,
) -> crate::semantic_capture::CurrentReceiptRefusal {
    use crate::semantic_capture::CurrentReceiptRefusal as Refusal;
    match error {
        image_query::ImageQueryRefusal::Unknown | image_query::ImageQueryRefusal::Unstable => {
            Refusal::Epoch
        }
        image_query::ImageQueryRefusal::Deadline => Refusal::Deadline,
        image_query::ImageQueryRefusal::Custody => Refusal::Custody,
        _ => Refusal::Audit,
    }
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

    /// Bind a frozen object table to this attested receipt: the publication
    /// domain must match, the receipt revalidates against fresh facts, and
    /// every required slot records its object eligibility plus retained ABI.
    /// Inactive in slice A.
    #[cfg_attr(not(test), allow(dead_code))] // Slice B/C call the freeze path.
    fn freeze_object_table_with<S>(
        self,
        frozen: FrozenObjectDescriptors<S>,
        readback: SemanticAttachmentReadback<'_>,
        watched: impl Fn(PinnedObjectId) -> Option<crate::discovery::identity::RetainedInventoryTarget>,
    ) -> ObjectResult<FrozenObjectTable<S>> {
        use crate::inventory_semantics::SemanticRefusal;
        if frozen.domain != self.domain {
            return Err(SemanticRefusal::Attachment);
        }
        self.validate_with(
            readback.domain,
            readback.policy,
            readback.descriptors,
            readback.retained,
            readback.owned_sides,
            watched,
        )?;
        let plan = self.subset.plan();
        let pins = self.subset.pins();
        let mut slots = BTreeMap::new();
        for indices in self.subset.required().values() {
            for index in indices {
                let slot = plan
                    .slots
                    .get(*index as usize)
                    .ok_or(SemanticRefusal::IncompleteProvider)?;
                let abi = pins
                    .abi_for(slot.object)
                    .ok_or(SemanticRefusal::IncompleteProvider)?;
                slots.insert(*index, (plan.object_slot_eligibility(*index), abi));
            }
        }
        Ok(FrozenObjectTable {
            descriptors: frozen,
            attached: self,
            slots,
        })
    }
}

/// An object table frozen against one attested receipt: the published rows,
/// the consumed receipt and per-required-slot eligibility plus retained ABI.
/// Inactive in slice A: no production path builds this yet.
#[cfg_attr(not(test), allow(dead_code))] // Slice B/C admit markers from this.
pub(crate) struct FrozenObjectTable<S> {
    descriptors: FrozenObjectDescriptors<S>,
    attached: AttachedSemanticSet,
    slots: BTreeMap<u32, (ObjectSlotEligibility, ElfAbi)>,
}

#[cfg_attr(not(test), allow(dead_code))] // Slice B/C admit markers from this.
impl<S> FrozenObjectTable<S> {
    /// Revalidate the receipt against fresh facts, then serve the stored
    /// eligibility: the frozen cookie plus retained ABI, or the recorded
    /// refusal. Slots outside the frozen binding refuse.
    fn eligible_slot_with(
        &self,
        slot: u32,
        readback: SemanticAttachmentReadback<'_>,
        watched: impl Fn(PinnedObjectId) -> Option<crate::discovery::identity::RetainedInventoryTarget>,
    ) -> ObjectResult<(u32, ElfAbi)> {
        use crate::inventory_semantics::SemanticRefusal;
        self.attached.validate_with(
            readback.domain,
            readback.policy,
            readback.descriptors,
            readback.retained,
            readback.owned_sides,
            watched,
        )?;
        match self.slots.get(&slot) {
            Some((ObjectSlotEligibility::Eligible { descriptor_index }, abi)) => {
                Ok((*descriptor_index, *abi))
            }
            Some((ObjectSlotEligibility::Refused { reason, .. }, _)) => Err(*reason),
            None => Err(SemanticRefusal::Attachment),
        }
    }

    /// The attested receipt this table is frozen against.
    pub(crate) fn semantic_set(&self) -> &AttachedSemanticSet {
        &self.attached
    }
}

#[cfg(test)]
#[path = "inventory_semantics_tests.rs"]
mod inventory_semantics_tests;

/// Retains exact reattach facts for every requested slot that gained a
/// link. Reattach overwrites: a replacement's new descriptor supersedes
/// the frozen one the rebuild pruned.
/// Retain the successfully attached static targets. Production and host
/// tests share this retention over their own attach outcomes.
pub(crate) fn retain_from_successful(
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
                held: None,
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
    group_static_slots_with_roots(
        slots,
        policy,
        object_has_unsafe,
        attach_targets,
        StaticRoots::Detailed,
    )
    .expect("every selected Detailed target has retained pinned facts")
}

// An opened Linux FD has at most ten decimal digits. Include the CString NUL
// in the bound; only the original pinned /proc/self/fd path reaches Counts.
const COUNTER_ATTACH_PATH_BYTES: usize = b"/proc/self/fd/".len() + 10 + 1;
const COUNTER_GROUP_DIAGNOSTIC_BYTES: usize = 256;

fn counter_attach_path_is_valid(path: &Path) -> bool {
    path.as_os_str()
        .as_encoded_bytes()
        .strip_prefix(b"/proc/self/fd/")
        .is_some_and(|digits| {
            !digits.is_empty() && digits.len() <= 10 && digits.iter().all(u8::is_ascii_digit)
        })
}

fn group_static_slots_with_roots(
    slots: &[Slot],
    policy: CapturePolicy,
    object_has_unsafe: bool,
    attach_targets: &BTreeMap<u32, (PathBuf, ElfAbi)>,
    roots: StaticRoots,
) -> Result<Vec<StaticGroup>> {
    if roots == StaticRoots::CounterBanks {
        if policy != CapturePolicy::AggregateOnly || object_has_unsafe {
            bail!("private Counts grouping requires its fixed aggregate-only roots");
        }
        for slot in slots {
            let (path, abi) = attach_targets
                .get(&slot.index)
                .context("private Counts target facts missing before grouping")?;
            if *abi != ElfAbi::Lp64 || !counter_attach_path_is_valid(path) {
                bail!("private Counts grouping requires an LP64 retained-FD attach path");
            }
        }
    }
    let return_program = if roots == StaticRoots::CounterBanks {
        "p11_counter_bank_return"
    } else {
        "p11_return"
    };
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
        let program = if roots == StaticRoots::CounterBanks {
            "p11_counter_bank_entry"
        } else {
            entry_program(&slot.semantics, policy, object_has_unsafe, *abi)
        };
        by_key
            .entry((path.clone(), program))
            .or_default()
            .push(StaticGroupMember {
                slot: slot.clone(),
                offset,
                cookie,
            });
    }
    Ok(by_key
        .into_iter()
        .map(|((path, entry_program), mut members)| {
            members.sort_by_key(|member| member.slot.index);
            StaticGroup {
                path,
                entry_program,
                return_program,
                members,
            }
        })
        .collect())
}

fn reserve_counter_multi_link_capacity(
    links: &mut Vec<RegisteredLink>,
    fresh_len: usize,
) -> std::result::Result<(), counter_banks::BankRefusal> {
    let extra = fresh_len
        .checked_mul(2)
        .ok_or(counter_banks::BankRefusal::Budget)?;
    links
        .len()
        .checked_add(extra)
        .ok_or(counter_banks::BankRefusal::Budget)?;
    links
        .try_reserve_exact(extra)
        .map_err(|_| counter_banks::BankRefusal::Budget)
}

fn retain_counter_multi_leaf(
    links: &mut Vec<RegisteredLink>,
    pairs: &mut pid_continuity::PairBook,
    program: &'static str,
    sites: &[(u64, u64)],
    slots_by_cookie: &BTreeMap<u64, u32>,
    attach: impl FnOnce() -> io::Result<OwnedFd>,
) -> io::Result<()> {
    if sites.is_empty()
        || !matches!(
            program,
            "p11_counter_bank_entry" | "p11_counter_bank_return"
        )
    {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    if links.len() == links.capacity() {
        return Err(io::Error::from_raw_os_error(libc::ENOMEM));
    }
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(sites.len())
        .map_err(|_| io::Error::from_raw_os_error(libc::ENOMEM))?;
    for &(_, cookie) in sites {
        let slot = slots_by_cookie
            .get(&cookie)
            .copied()
            .filter(|slot| *slot == p11scope_ebpf_common::cookie_slot(cookie))
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        if slots.last().is_some_and(|old| *old >= slot) {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        slots.push(slot);
    }
    let mut fds = Vec::new();
    fds.try_reserve_exact(1)
        .map_err(|_| io::Error::from_raw_os_error(libc::ENOMEM))?;
    // All fallible allocation/validation precedes acquisition. The acquired
    // FD enters this already-paid registry before a later bisect can fail.
    let fd = attach()?;
    fds.push(fd);
    links.push(RegisteredLink::MultiUProbe {
        program,
        slots,
        fds,
        registration: pairs.register(),
    });
    Ok(())
}

fn validate_counter_group_retirement(
    links: &[RegisteredLink],
    requested: &BTreeSet<u32>,
) -> Result<()> {
    if let Some(slot) = find_partial_multi_member(links, requested) {
        bail!(
            "private Counts slot {slot} requires whole-group retirement; published groups cannot rebuild"
        );
    }
    Ok(())
}

fn group_site_failure(
    program: &'static str,
    path: &Path,
    offset: u64,
    error: &io::Error,
) -> String {
    if matches!(
        program,
        "p11_counter_bank_entry" | "p11_counter_bank_return"
    ) {
        use std::fmt::Write as _;
        let shown = if counter_attach_path_is_valid(path) {
            path
        } else {
            Path::new("<invalid FD path>")
        };
        // At most 23 ASCII program bytes, 24 FD-path bytes, 18 offset bytes,
        // 11 errno bytes and 13 separators: 89 UTF-8 bytes total. The fallback
        // path/error labels are shorter. No intermediate String is allocated.
        let mut message = String::with_capacity(COUNTER_GROUP_DIAGNOSTIC_BYTES);
        write!(message, "{program} at {}+{offset:#x}: ", shown.display())
            .expect("String formatting");
        match error.raw_os_error() {
            Some(errno) => write!(message, "errno {errno}"),
            None => write!(message, "errno unavailable"),
        }
        .expect("String formatting");
        message
    } else {
        format!(
            "{program} at {}+{offset:#x}: {}",
            path.display(),
            error_chain(error)
        )
    }
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

/// Publish the kept bundles through the same registry path used by initial
/// attachment and survivor rebuilds. Retained facts follow live links.
fn publish_kept_multi_bundles(
    links: &mut Vec<RegisteredLink>,
    retained: &mut BTreeMap<u32, RetainedStaticTarget>,
    bundles: Vec<MultiLinkBundle<OwnedFd>>,
    targets: &[RetainedStaticTarget],
    pairs: &mut pid_continuity::PairBook,
) {
    for bundle in bundles {
        links.push(RegisteredLink::MultiUProbe {
            program: bundle.program,
            slots: bundle.slots,
            fds: bundle.links,
            registration: pairs.register(),
        });
    }
    for target in targets {
        if links_cover_slot(links, target.slot.index) {
            retained.insert(target.slot.index, target.clone());
        }
    }
    prune_linkless_retained(retained, links);
}

/// Invalidate selected registration facts before taking ownership out of the
/// live registry. The native detach callback cannot see an old valid stamp.
fn extract_selected_links(
    links: &mut Vec<RegisteredLink>,
    pairs: &mut pid_continuity::PairBook,
    mut select: impl FnMut(&RegisteredLink) -> bool,
) -> Vec<RegisteredLink> {
    let selected: Vec<_> = links.iter().map(&mut select).collect();
    let affected = links
        .iter()
        .zip(&selected)
        .filter(|(_, selected)| **selected)
        .flat_map(|(link, _)| link.slots().iter().copied())
        .collect();
    pairs.invalidate(&affected);
    let mut taken = Vec::new();
    let mut retained = Vec::new();
    for (link, selected) in std::mem::take(links).into_iter().zip(selected) {
        if selected {
            taken.push(link);
        } else {
            retained.push(link);
        }
    }
    *links = retained;
    taken
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
#[cfg(test)]
fn attach_target_groups_with<T>(
    groups: &[StaticGroup],
    completed_at: impl FnMut(&Slot) -> Option<u64>,
    mut attach_link: impl FnMut(&'static str, &Path, &[(u64, u64)], bool) -> io::Result<T>,
) -> Result<(Vec<MultiLinkBundle<T>>, AttachOutcome), BackendFallbackRequired> {
    attach_target_groups_observed_with(groups, completed_at, |program, path, sites, is_return| {
        pid_continuity::NativeAttempt::run(pid_continuity::comparable_monotonic_ns, || {
            attach_link(program, path, sites, is_return)
        })
    })
}

fn attach_target_groups_observed_with<T>(
    groups: &[StaticGroup],
    completed_at: impl FnMut(&Slot) -> Option<u64>,
    attach_link: impl FnMut(
        &'static str,
        &Path,
        &[(u64, u64)],
        bool,
    ) -> pid_continuity::NativeAttempt<T, io::Error>,
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
    mut attach_link: impl FnMut(
        &'static str,
        &Path,
        &[(u64, u64)],
        bool,
    ) -> pid_continuity::NativeAttempt<T, io::Error>,
) -> Result<(Vec<MultiLinkBundle<T>>, AttachOutcome), BackendFallbackRequired> {
    let mut successful = BTreeSet::new();
    let mut failures = Vec::new();
    let mut completed = Vec::new();
    let mut continuity_rounds = Vec::new();
    let mut bundles = Vec::new();
    let mut links_attached = 0usize;
    for group in groups {
        let mut timing = pid_continuity::RoundClock::default();
        let sites: Vec<(u64, u64)> = group
            .members
            .iter()
            .map(|member| (member.offset, member.cookie))
            .collect();
        let (return_links, return_refused) = match bisect_attach(
            &mut |slice| {
                let attempt = attach_link(group.return_program, &group.path, slice, true);
                timing.observe_call(attempt.started_ns);
                attempt.result
            },
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
                        continuity_rounds,
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
                group_site_failure(
                    group.return_program,
                    &group.path,
                    member.offset,
                    &site.error,
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
                static_endpoint(group.return_program, member.slot.index)
                    .expect("selected return program is a static endpoint"),
            );
        }
        if !return_links.is_empty() {
            bundles.push(MultiLinkBundle {
                program: group.return_program,
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
            &mut |slice| {
                let attempt = attach_link(group.entry_program, &group.path, slice, false);
                timing.observe_call(attempt.started_ns);
                attempt.result
            },
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
                        continuity_rounds,
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
                group_site_failure(group.entry_program, &group.path, member.offset, &site.error),
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
            continuity_rounds.push(timing.finish(entry_slots.clone()));
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
            continuity_rounds,
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
#[cfg(test)]
fn reattach_rebuilt_groups_with<T>(
    groups: &[StaticGroup],
    completed_at: impl FnMut(&Slot) -> Option<u64>,
    mut attach_link: impl FnMut(&'static str, &Path, &[(u64, u64)], bool) -> io::Result<T>,
    detach_bundles: impl FnMut(Vec<MultiLinkBundle<T>>),
) -> (Vec<MultiLinkBundle<T>>, AttachOutcome) {
    reattach_rebuilt_groups_observed_with(
        groups,
        completed_at,
        |program, path, sites, is_return| {
            pid_continuity::NativeAttempt::run(pid_continuity::comparable_monotonic_ns, || {
                attach_link(program, path, sites, is_return)
            })
        },
        detach_bundles,
    )
}

fn reattach_rebuilt_groups_observed_with<T>(
    groups: &[StaticGroup],
    mut completed_at: impl FnMut(&Slot) -> Option<u64>,
    mut attach_link: impl FnMut(
        &'static str,
        &Path,
        &[(u64, u64)],
        bool,
    ) -> pid_continuity::NativeAttempt<T, io::Error>,
    mut detach_bundles: impl FnMut(Vec<MultiLinkBundle<T>>),
) -> (Vec<MultiLinkBundle<T>>, AttachOutcome) {
    let mut kept = Vec::new();
    let mut successful = BTreeSet::new();
    let mut failures = Vec::new();
    let mut completed = Vec::new();
    let mut continuity_rounds = Vec::new();
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
                return_program: group.return_program,
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
                            continuity_rounds,
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
                        continuity_rounds,
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
                continuity_rounds.extend(outcome.continuity_rounds);
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
            continuity_rounds,
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

#[cfg(test)]
/// Attach scheduling and retention over injected link I/O: production
/// passes the live linker, host tests a scripted one. The scheduling,
/// pairing and completion rules are identical either way.
pub(crate) fn attach_targets_with(
    slots: &[Slot],
    policy: CapturePolicy,
    object_has_unsafe: bool,
    abi_for: impl FnMut(&Slot) -> Result<ElfAbi>,
    mut attach: impl FnMut(&'static str, &Slot, UProbeAttachPoint<'static>) -> Result<()>,
    completed_at: impl FnMut(&Slot) -> Option<u64>,
) -> Result<AttachOutcome> {
    attach_targets_observed_with(
        slots,
        policy,
        object_has_unsafe,
        abi_for,
        |program, slot, point| {
            pid_continuity::NativeAttempt::run(pid_continuity::comparable_monotonic_ns, || {
                attach(program, slot, point)
            })
        },
        completed_at,
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StaticRoots {
    Detailed,
    CounterBanks,
}

#[cfg(test)]
fn attach_targets_observed_with(
    slots: &[Slot],
    policy: CapturePolicy,
    object_has_unsafe: bool,
    abi_for: impl FnMut(&Slot) -> Result<ElfAbi>,
    attach: impl FnMut(
        &'static str,
        &Slot,
        UProbeAttachPoint<'static>,
    ) -> pid_continuity::NativeAttempt<(), anyhow::Error>,
    completed_at: impl FnMut(&Slot) -> Option<u64>,
) -> Result<AttachOutcome> {
    attach_targets_observed_with_roots(
        slots,
        policy,
        object_has_unsafe,
        StaticRoots::Detailed,
        abi_for,
        attach,
        completed_at,
    )
}

fn attach_targets_observed_with_roots(
    slots: &[Slot],
    policy: CapturePolicy,
    object_has_unsafe: bool,
    roots: StaticRoots,
    mut abi_for: impl FnMut(&Slot) -> Result<ElfAbi>,
    mut attach: impl FnMut(
        &'static str,
        &Slot,
        UProbeAttachPoint<'static>,
    ) -> pid_continuity::NativeAttempt<(), anyhow::Error>,
    mut completed_at: impl FnMut(&Slot) -> Option<u64>,
) -> Result<AttachOutcome> {
    // Resolve every retained target ABI before the first return attachment.
    // This keeps each return/entry pair bound to the same pinned object fact.
    let targets = slots
        .iter()
        .map(|slot| abi_for(slot).map(|abi| (slot, abi)))
        .collect::<Result<Vec<_>>>()?;
    if roots == StaticRoots::CounterBanks
        && (policy != CapturePolicy::AggregateOnly
            || object_has_unsafe
            || targets.iter().any(|(_, abi)| *abi != ElfAbi::Lp64))
    {
        bail!("private Counts bank attachment requires the LP64 aggregate-only fixed pair");
    }
    let return_program = if roots == StaticRoots::CounterBanks {
        "p11_counter_bank_return"
    } else {
        "p11_return"
    };
    let mut successful = BTreeSet::new();
    let mut failures = Vec::new();
    let mut completed = Vec::new();
    let mut continuity_rounds = Vec::new();
    let mut timings = BTreeMap::<u32, pid_continuity::RoundClock>::new();
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
        let attempt = attach(return_program, slot, slot_attach_point(slot));
        timings
            .entry(slot.index)
            .or_default()
            .observe_call(attempt.started_ns);
        match attempt.result {
            Ok(()) => {
                successful.insert(
                    static_endpoint(return_program, slot.index)
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
                        continuity_rounds,
                        exhausted: true,
                    });
                }
                failures.push((slot.index, format!("{error:#}")));
            }
        }
    }

    let entry_programs: &[&str] = if roots == StaticRoots::CounterBanks {
        &["p11_counter_bank_entry"]
    } else if object_has_unsafe {
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
                || (roots == StaticRoots::Detailed
                    && entry_program(&slot.semantics, policy, object_has_unsafe, *abi) != *program)
            {
                continue;
            }
            let attempt = attach(program, slot, slot_attach_point(slot));
            timings
                .entry(slot.index)
                .or_default()
                .observe_call(attempt.started_ns);
            match attempt.result {
                Ok(()) => {
                    successful.insert(
                        static_endpoint(program, slot.index)
                            .expect("selected entry program is a static endpoint"),
                    );
                    completed.push((slot.index, completed_at(slot)));
                    continuity_rounds.push(
                        timings
                            .remove(&slot.index)
                            .expect("return timing exists")
                            .finish(vec![slot.index]),
                    );
                }
                Err(error) => {
                    if is_fd_exhaustion(&error) {
                        failures.push(exhausted(slot, &successful, &error));
                        fail_unfinished(&mut failures, &completed);
                        return Ok(AttachOutcome {
                            successful,
                            failures,
                            completed,
                            continuity_rounds,
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
        continuity_rounds,
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

/// Exact bytes of one frozen object descriptor row for map publication.
/// `ObjectDescriptorWire` is 16 bytes of plain data with no padding; the
/// encoding spells every field so a layout drift fails loudly here rather
/// than in the kernel.
fn object_descriptor_row_bytes(row: &ObjectDescriptorWire) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&row.function.to_le_bytes());
    bytes[4..6].copy_from_slice(&row.input_args);
    bytes[6..8].copy_from_slice(&row.result_args);
    bytes[8..12].copy_from_slice(&row.template_args);
    bytes[12] = row.find_capacity_arg;
    bytes[13] = row.find_count_arg;
    bytes[14] = row.action;
    bytes[15] = row.guard;
    bytes
}

/// Publish the subordinate-custody maps before links: every canonical
/// object descriptor row with exact readback, the zero template verified
/// clean, and the side table capacity tied to START (no cap increase).
/// Freezing stays with the standard freeze machinery through
/// BASE_POLICY_MAPS.
fn publish_object_custody_maps(ebpf: &mut Ebpf) -> Result<()> {
    let expected = publish_object_descriptors();
    let mut table: Array<_, [u8; 16]> = Array::try_from(
        ebpf.map_mut("OBJECT_DESCRIPTORS")
            .context("OBJECT_DESCRIPTORS map")?,
    )?;
    for (index, row) in expected.iter().enumerate() {
        table
            .set(index as u32, object_descriptor_row_bytes(row), 0)
            .with_context(|| format!("publishing OBJECT_DESCRIPTORS row {index}"))?;
    }
    for (index, row) in expected.iter().enumerate() {
        let actual: [u8; 16] = table
            .get(&(index as u32), 0)
            .with_context(|| format!("reading OBJECT_DESCRIPTORS row {index}"))?;
        if actual != object_descriptor_row_bytes(row) {
            bail!("OBJECT_DESCRIPTORS exact readback differs at row {index}");
        }
    }
    let zero: Array<_, [u8; 432]> =
        Array::try_from(ebpf.map("OBJECT_ZERO").context("OBJECT_ZERO map")?)?;
    let template: [u8; 432] = zero.get(&0, 0).context("reading OBJECT_ZERO row 0")?;
    if template != [0u8; 432] {
        bail!("OBJECT_ZERO row 0 is not clean");
    }
    let start_max = {
        let map = ebpf.map("START").context("START map")?;
        let Map::HashMap(data) = map else {
            bail!("unexpected START map variant");
        };
        read_map_metadata("START", data)?.max_entries
    };
    let map = ebpf.map("OBJECT_START").context("OBJECT_START map")?;
    let Map::HashMap(data) = map else {
        bail!("unexpected OBJECT_START map variant");
    };
    validate_map_metadata(
        "OBJECT_START",
        data,
        map_metadata(MapType::Hash, 16, 432, start_max, 0),
    )?;
    Ok(())
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

type ObjectRows = [ObjectDescriptorWire; MAX_DESCRIPTORS as usize];
type ObjectResult<T> = std::result::Result<T, crate::inventory_semantics::SemanticRefusal>;

/// Verified frozen object descriptor rows. Ordinary consumers may validate the
/// producer's full record before discarding its tail; only start_attested places
/// a table in Session::object_decode for the semantic admission lane.
pub(crate) struct ObjectDecodeTable {
    rows: Arc<ObjectRows>,
}

impl ObjectDecodeTable {
    pub(crate) fn rows(&self) -> &ObjectRows {
        &self.rows
    }
}

/// Select wire decoding independently of attested semantic eligibility. A
/// producer-enabled ordinary session requires its own verified map readback;
/// an attested session can share its already verified immutable rows.
pub(crate) fn object_transport_rows_with(
    policy: CapturePolicy,
    attested: Option<&Arc<ObjectRows>>,
    readback: impl FnOnce() -> Result<Arc<ObjectRows>>,
) -> Result<Option<Arc<ObjectRows>>> {
    match policy {
        CapturePolicy::Allowlisted => match attested {
            Some(rows) => Ok(Some(Arc::clone(rows))),
            None => readback().map(Some),
        },
        CapturePolicy::AggregateOnly | CapturePolicy::UnsafeUnvalidatedMetadata => Ok(None),
    }
}

/// Verify the frozen transport rows: read back every live
/// OBJECT_DESCRIPTORS row and require the exact canonical table the
/// loader published and froze. Any absence or disagreement refuses the
/// session rather than decoding tails against wrong rows. This verification
/// does not itself attest an attachment or authorize semantic admission.
fn freeze_object_decode_table(ebpf: &Ebpf) -> Result<ObjectDecodeTable> {
    use p11scope_ebpf_common::object_wire::publish_object_descriptors;
    let expected = publish_object_descriptors();
    let table: Array<_, [u8; 16]> = Array::try_from(
        ebpf.map("OBJECT_DESCRIPTORS")
            .context("OBJECT_DESCRIPTORS map")?,
    )?;
    for (index, row) in expected.iter().enumerate() {
        let actual: [u8; 16] = table
            .get(&(index as u32), 0)
            .with_context(|| format!("reading OBJECT_DESCRIPTORS row {index}"))?;
        if actual != object_descriptor_row_bytes(row) {
            bail!("OBJECT_DESCRIPTORS transport readback differs at row {index}");
        }
    }
    Ok(ObjectDecodeTable {
        rows: Arc::new(expected),
    })
}

/// Exact inputs for one attested-receipt validation, bundled so the object
/// freeze and later eligibility checks revalidate against the same facts.
/// Inactive in slice A.
#[cfg_attr(not(test), allow(dead_code))] // Slice B/C call the freeze path.
struct SemanticAttachmentReadback<'a> {
    domain: capture::NativeDomainId,
    policy: CapturePolicy,
    descriptors: Result<Vec<SlotSemantics>>,
    retained: &'a BTreeMap<u32, RetainedStaticTarget>,
    owned_sides: &'a BTreeSet<StaticEndpoint>,
}

/// Object rows published, read back and frozen on one state for one domain.
/// Inactive in slice A: no production map exists yet.
#[cfg_attr(not(test), allow(dead_code))] // Slice B/C call the freeze path.
struct FrozenObjectDescriptors<S> {
    state: S,
    domain: capture::NativeDomainId,
    rows: ObjectRows,
}

/// Publish the canonical 105 rows in order, require an exact readback,
/// freeze the same resource, then require an exact post-freeze readback.
/// Any I/O failure or inexact table refuses; only a proven table freezes.
#[cfg_attr(not(test), allow(dead_code))] // Slice B/C call the freeze path.
fn publish_and_freeze_object_descriptors_with<S>(
    state: S,
    domain: capture::NativeDomainId,
    mut set: impl FnMut(&mut S, u32, ObjectDescriptorWire) -> Result<()>,
    mut readback: impl FnMut(&mut S) -> Result<Vec<ObjectDescriptorWire>>,
    freeze: impl FnOnce(&mut S) -> Result<()>,
) -> ObjectResult<FrozenObjectDescriptors<S>> {
    use crate::inventory_semantics::SemanticRefusal;
    let expected = publish_object_descriptors();
    let mut state = state;
    for (index, row) in expected.iter().copied().enumerate() {
        set(&mut state, index as u32, row).map_err(|_| SemanticRefusal::Descriptor)?;
    }
    let actual = readback(&mut state).map_err(|_| SemanticRefusal::Descriptor)?;
    if actual.as_slice() != expected.as_slice() {
        return Err(SemanticRefusal::Descriptor);
    }
    freeze(&mut state).map_err(|_| SemanticRefusal::Descriptor)?;
    let recheck = readback(&mut state).map_err(|_| SemanticRefusal::Descriptor)?;
    if recheck.as_slice() != expected.as_slice() {
        return Err(SemanticRefusal::Descriptor);
    }
    Ok(FrozenObjectDescriptors {
        state,
        domain,
        rows: expected,
    })
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

/// Whether the embedded Detailed object carries stubbed attribute capture.
/// Entry capture is inlined, so the rule proves its scalar reader is called,
/// and identifies the return adapter exactly, without confusing its closure
/// with its body. Panics on missing, ambiguous or half-wired evidence.
/// One copy of the rule: this delegates to the production probe.
#[cfg(test)]
pub(crate) fn embedded_object_is_stubbed() -> bool {
    let parsed =
        aya_obj::Object::parse(crate::EBPF_OBJECT).expect("embedded Detailed object parses");
    embedded_object_capture_is_stubbed(parsed)
}

fn embedded_adapter_symbol_matches(symbol: &str, helper: &str) -> bool {
    let Some(path) = symbol.strip_prefix("_RNvC") else {
        return false;
    };
    let path = if let Some(disambiguated) = path.strip_prefix('s') {
        let Some((base62, path)) = disambiguated.split_once('_') else {
            return false;
        };
        if base62.is_empty() || !base62.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return false;
        }
        path
    } else {
        path
    };
    path == format!("13p11scope_ebpf{}{helper}", helper.len())
}

/// Test-only entry lookup: one copy of the rule, panicking where the
/// production probe refuses.
#[cfg(test)]
fn embedded_object_capture_entry(parsed: aya_obj::Object) -> (aya_obj::Function, u32) {
    probed_capture_entry(parsed).expect("embedded Detailed bytes must probe")
}

/// Test-only reachability walk: one copy of the rule, panicking where
/// the production probe refuses.
#[cfg(test)]
fn embedded_entry_reaches_reader(entry: &aya_obj::Function, reader_id: u32) -> bool {
    probed_entry_reaches_reader(entry, reader_id).expect("embedded Detailed bytes must probe")
}

/// Test-only stub rule: one copy of the rule, panicking where the
/// production probe refuses.
#[cfg(test)]
fn embedded_object_capture_is_stubbed(parsed: aya_obj::Object) -> bool {
    probed_capture_is_stubbed(parsed).expect("embedded Detailed bytes must probe")
}

/// Flavor of the embedded Detailed BPF object, probed from its bytes rather
/// than from the Cargo features the observer was built with. `stubbed` is
/// true when object-attribute capture is stubbed (P0); `unsafe_present` is
/// true when the unsafe-unvalidated-metadata decoders are compiled in.
/// Output and policy report the bytes: a stale or mismatched embedded object
/// must never let output claim P0 while the loaded program does FULL reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EmbeddedFlavor {
    pub stubbed: bool,
    pub unsafe_present: bool,
}

/// Why the embedded flavor could not be determined: the object does not
/// parse, or its capture evidence is missing, ambiguous or half-wired.
/// A production refusal, never a panic.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FlavorProbeError {
    reason: String,
}

impl FlavorProbeError {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    pub(crate) fn reason(&self) -> &str {
        &self.reason
    }
}

impl std::fmt::Display for FlavorProbeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for FlavorProbeError {}

/// Production byte probe: link the entry root and locate the request
/// reader. The test-only `embedded_object_capture_entry` delegates here;
/// every missing or ambiguous input is an error (a refusal), never a panic.
fn probed_capture_entry(
    mut parsed: aya_obj::Object,
) -> Result<(aya_obj::Function, u32), FlavorProbeError> {
    let reader = "p11_request_cell";
    let mut matches = parsed
        .functions
        .values()
        .filter(|function| function.name == reader);
    let function = matches
        .next()
        .ok_or_else(|| FlavorProbeError::new("embedded Detailed object lacks request reader"))?;
    if matches.next().is_some() {
        return Err(FlavorProbeError::new("ambiguous embedded request reader"));
    }
    let reader_id = parsed
        .btf
        .as_ref()
        .ok_or_else(|| FlavorProbeError::new("embedded object needs original BTF"))?
        .id_by_type_name_kind(reader, aya_obj::btf::BtfKind::Func)
        .map_err(|_| FlavorProbeError::new("embedded request reader needs original BTF FUNC"))?;
    if function.func_info.func_info.len() != 1 {
        return Err(FlavorProbeError::new("ambiguous request function info"));
    }
    if function.func_info.func_info[0].type_id != reader_id {
        return Err(FlavorProbeError::new(
            "request reader function info must bind its original BTF FUNC",
        ));
    }
    let entry = parsed
        .programs
        .get("p11_entry")
        .ok_or_else(|| FlavorProbeError::new("embedded Detailed object lacks entry"))?;
    let key = entry.function_key();
    if parsed
        .functions
        .values()
        .filter(|function| function.name == "p11_entry")
        .count()
        != 1
    {
        return Err(FlavorProbeError::new("ambiguous embedded entry function"));
    }
    if parsed
        .functions
        .get(&key)
        .is_none_or(|function| function.name != "p11_entry")
    {
        return Err(FlavorProbeError::new("ambiguous embedded entry function"));
    }
    let text_sections = parsed
        .functions
        .keys()
        .map(|(section, _)| *section)
        .collect();
    // Link only the entry root. Inspect return size independently, so changing
    // a return body cannot fabricate entry-reader reachability.
    parsed.programs.retain(|name, _| name == "p11_entry");
    parsed.relocate_calls(&text_sections).map_err(|error| {
        FlavorProbeError::new(format!("embedded entry calls do not relocate: {error}"))
    })?;
    let entry = parsed
        .functions
        .remove(&key)
        .ok_or_else(|| FlavorProbeError::new("linked entry went missing after relocation"))?;
    Ok((entry, reader_id))
}

/// Production byte probe: whether the linked entry reaches the request
/// reader through real calls. The test-only `embedded_entry_reaches_reader`
/// delegates here: malformed function info is an error, never a panic.
fn probed_entry_reaches_reader(
    entry: &aya_obj::Function,
    reader_id: u32,
) -> Result<bool, FlavorProbeError> {
    use std::ops::Bound::{Excluded, Unbounded};
    let functions: BTreeMap<_, _> = entry
        .func_info
        .func_info
        .iter()
        .map(|info| (info.insn_off as usize, info.type_id))
        .collect();
    if functions.len() != entry.func_info.func_info.len() {
        return Err(FlavorProbeError::new("ambiguous linked function info"));
    }
    if functions.first_key_value().map(|(start, _)| *start) != Some(0) {
        return Err(FlavorProbeError::new(
            "linked entry function info must start at 0",
        ));
    }
    if !functions
        .keys()
        .all(|start| *start < entry.instructions.len())
    {
        return Err(FlavorProbeError::new(
            "linked entry function info out of range",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut pending = vec![0];
    while let Some(start) = pending.pop() {
        if !seen.insert(start) {
            continue;
        }
        let end = functions
            .range((Excluded(start), Unbounded))
            .next()
            .map_or(entry.instructions.len(), |(end, _)| *end);
        for (at, instruction) in entry.instructions.iter().enumerate().take(end).skip(start) {
            if instruction.code == 0x85 && instruction.src_reg() == 1 {
                let target = (at + 1)
                    .checked_add_signed(instruction.imm as isize)
                    .ok_or_else(|| {
                        FlavorProbeError::new("linked entry call target is out of range")
                    })?;
                if !functions.contains_key(&target) {
                    return Err(FlavorProbeError::new(
                        "linked entry call lacks exact function info",
                    ));
                }
                pending.push(target);
            }
        }
    }
    Ok(seen.iter().any(|start| functions[start] == reader_id))
}

/// Production byte probe: stubbed vs wired attribute capture from parsed
/// bytes. The test-only `embedded_object_capture_is_stubbed` delegates
/// here: the return adapter must match exactly and be small exactly when
/// the entry root does not reach the request reader. Missing, ambiguous or
/// half-wired evidence is an error (a refusal), never a panic.
fn probed_capture_is_stubbed(parsed: aya_obj::Object) -> Result<bool, FlavorProbeError> {
    let mut matches = parsed.functions.values().filter(|function| {
        embedded_adapter_symbol_matches(&function.name, "object_emit_get_attributes")
    });
    let emit = matches
        .next()
        .ok_or_else(|| {
            FlavorProbeError::new("embedded Detailed object has no exact return adapter")
        })?
        .instructions
        .len();
    if matches.next().is_some() {
        return Err(FlavorProbeError::new(
            "embedded Detailed object has several exact return adapters",
        ));
    }
    let emit_stub = emit < 300;
    let (entry, reader_id) = probed_capture_entry(parsed)?;
    let entry_stub = !probed_entry_reaches_reader(&entry, reader_id)?;
    if entry_stub != emit_stub {
        return Err(FlavorProbeError::new(
            "half-wired embedded object: the entry program and the return adapter disagree about attribute capture",
        ));
    }
    Ok(entry_stub)
}

/// Production byte probe: whether the unsafe-unvalidated-metadata decoders
/// are present. Present means every unsafe entry program and every
/// unsafe-only policy map is in the object; absent means none is. Any
/// mixture is half-wired evidence and an error, never a guess.
fn probed_unsafe_is_present(parsed: &aya_obj::Object) -> Result<bool, FlavorProbeError> {
    let mut present = Vec::new();
    let mut absent = Vec::new();
    for name in UNSAFE_PROGRAMS {
        if parsed.programs.contains_key(name) {
            present.push(name);
        } else {
            absent.push(name);
        }
    }
    for (name, _) in FEATURE_POLICY_MAPS {
        if parsed.maps.contains_key(name) {
            present.push(name);
        } else {
            absent.push(name);
        }
    }
    if absent.is_empty() {
        Ok(true)
    } else if present.is_empty() {
        Ok(false)
    } else {
        Err(FlavorProbeError::new(format!(
            "half-wired embedded object (unsafe markers present: {}, absent: {})",
            present.join(","),
            absent.join(",")
        )))
    }
}

/// Probe the flavor of one Detailed object's bytes: parse, then derive
/// stubbed-vs-wired capture and unsafe-decoder presence from the bytes.
/// Unparseable bytes and missing, ambiguous or half-wired evidence are
/// errors (a refusal), never a panic.
pub(crate) fn embedded_flavor_from_bytes(
    object: &[u8],
) -> Result<EmbeddedFlavor, FlavorProbeError> {
    let parsed = aya_obj::Object::parse(object).map_err(|error| {
        FlavorProbeError::new(format!("embedded Detailed object does not parse: {error}"))
    })?;
    let unsafe_present = probed_unsafe_is_present(&parsed)?;
    let stubbed = probed_capture_is_stubbed(parsed)?;
    Ok(EmbeddedFlavor {
        stubbed,
        unsafe_present,
    })
}

static EMBEDDED_FLAVOR: OnceLock<Result<EmbeddedFlavor, FlavorProbeError>> = OnceLock::new();

/// The embedded Detailed object's flavor, parsed once per process and cached.
/// Test builds honor a held override first (see
/// [`hold_embedded_flavor_for_test`]); every other read shares the cache.
pub(crate) fn embedded_flavor() -> Result<EmbeddedFlavor, FlavorProbeError> {
    #[cfg(test)]
    if let Some(overridden) = test_flavor_override() {
        return overridden;
    }
    EMBEDDED_FLAVOR
        .get_or_init(|| embedded_flavor_from_bytes(crate::EBPF_OBJECT))
        .clone()
}

#[cfg(test)]
thread_local! {
    static TEST_FLAVOR_OVERRIDE: std::cell::RefCell<
        Option<Result<EmbeddedFlavor, FlavorProbeError>>,
    > = const { std::cell::RefCell::new(None) };
}

/// Test seam: hold a planted flavor (or probe error) on this thread while
/// the guard lives. The injection is per thread (the pidns test-seam
/// shape), so a test sees it on its own thread only and no other test is
/// affected. The previous value restores on drop, also on a panic; nested
/// holders compose.
#[cfg(test)]
pub(crate) struct FlavorOverrideGuard {
    previous: Option<Result<EmbeddedFlavor, FlavorProbeError>>,
}

#[cfg(test)]
impl Drop for FlavorOverrideGuard {
    fn drop(&mut self) {
        TEST_FLAVOR_OVERRIDE.with(|cell| *cell.borrow_mut() = self.previous.take());
    }
}

#[cfg(test)]
pub(crate) fn hold_embedded_flavor_for_test(
    flavor: Result<EmbeddedFlavor, FlavorProbeError>,
) -> FlavorOverrideGuard {
    let previous = TEST_FLAVOR_OVERRIDE.with(|cell| cell.borrow_mut().replace(flavor));
    FlavorOverrideGuard { previous }
}

#[cfg(test)]
fn test_flavor_override() -> Option<Result<EmbeddedFlavor, FlavorProbeError>> {
    TEST_FLAVOR_OVERRIDE.with(|cell| cell.borrow().clone())
}

/// The probed flavor must match the build features: a stale or mismatched
/// embedded object refuses with one plain message naming both values.
/// Pure over its argument so tests plant flavors without touching bytes.
pub(crate) fn check_flavor_against_build(probed: EmbeddedFlavor) -> Result<EmbeddedFlavor> {
    let expect_stubbed = cfg!(feature = "stub-object-attributes");
    if probed.stubbed != expect_stubbed {
        let (expected, actual) = if expect_stubbed {
            ("stubbed (P0)", "wired (FULL)")
        } else {
            ("FULL", "stubbed (P0)")
        };
        bail!(
            "embedded BPF object flavor mismatch: build expects {expected} object-attribute capture, embedded bytes are {actual} (stale or mismatched embedded object; rebuild p11scope from a clean target directory)"
        );
    }
    let expect_unsafe = cfg!(feature = "unsafe-unvalidated-metadata");
    if probed.unsafe_present != expect_unsafe {
        let (expected, actual) = if expect_unsafe {
            ("with", "lack")
        } else {
            ("without", "contain")
        };
        bail!(
            "embedded BPF object flavor mismatch: build was compiled {expected} unsafe-unvalidated-metadata, embedded bytes {actual} its decoders (stale or mismatched embedded object; rebuild p11scope from a clean target directory)"
        );
    }
    Ok(probed)
}

/// The cached probed flavor, refused unless it matches the build features.
/// Missing, ambiguous or half-wired evidence refuses here, before any
/// attach or load.
pub(crate) fn checked_embedded_flavor() -> Result<EmbeddedFlavor> {
    match embedded_flavor() {
        Ok(probed) => check_flavor_against_build(probed),
        Err(error) => bail!(
            "cannot determine embedded BPF object flavor: {} (stale or mismatched embedded object; rebuild p11scope from a clean target directory)",
            error.reason()
        ),
    }
}

/// Whether a raw errno is the kernel verifier's budget refusal: E2BIG is
/// what BPF_PROG_LOAD returns when the program exceeds the complexity
/// limit. Every other errno keeps its own meaning.
pub(crate) fn is_verifier_budget_errno(errno: Option<i32>) -> bool {
    errno == Some(libc::E2BIG)
}

/// Load-refusal detector for doctor/diagnostics: true only for a genuine
/// BPF program-load refusal on verifier budget (E2BIG from BPF_PROG_LOAD).
/// Permission, map-policy, identity and malformed-object failures — and
/// every non-load error — return false and keep their own errors.
pub(crate) fn is_verifier_budget_refusal(error: &aya::programs::ProgramError) -> bool {
    match error {
        aya::programs::ProgramError::LoadError { io_error, .. } => {
            is_verifier_budget_errno(io_error.raw_os_error())
        }
        _ => false,
    }
}

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
    load_capture_object_bytes_with_images(
        btf,
        events_bytes,
        discovery_bytes,
        full_images,
        crate::EBPF_OBJECT,
    )
}

fn load_capture_object_bytes_with_images(
    btf: &Btf,
    events_bytes: u32,
    discovery_bytes: u32,
    full_images: bool,
    object: &[u8],
) -> std::result::Result<Ebpf, aya::EbpfError> {
    EbpfLoader::new()
        .btf(Some(btf))
        .allow_unsupported_maps()
        .map_max_entries("EVENTS", events_bytes)
        .map_max_entries("DISCOVERY", discovery_bytes)
        .map_max_entries("IMAGE_CONTINUITY", if full_images { 16_384 } else { 1 })
        .map_max_entries("IMAGE_TGID_INDEX", if full_images { 16_384 } else { 1 })
        .map_max_entries("IMAGE_QUERY_REQUESTS", if full_images { 1_024 } else { 1 })
        .load(object)
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
/// is preserved and no item is ever dropped here. Staging stops at the
/// shared allowance; beyond it records wait in the kernel ring, where
/// overflow is counted by the producer as ring loss.
#[derive(Default)]
pub(crate) struct DiscoveryStage {
    items: std::collections::VecDeque<events::DiscoveryItem>,
}

/// What one staging call moved: how many items entered the FIFO, and
/// whether staging stopped at the shared allowance with the quantum
/// unspent (the ring still holds whatever it holds; only the next drain
/// settles the FIFO and frees the allowance).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DiscoveryStageOutcome {
    pub(crate) staged: usize,
    pub(crate) capacity_blocked: bool,
}

impl DiscoveryStage {
    /// About 3.7 MiB of 920-byte records, more than one full shared-scope
    /// ring.
    pub(crate) const CAPACITY: usize = 4096;

    /// Moves up to `quantum` items from `next` into the FIFO without
    /// letting the FIFO exceed `shared_cap` — the shared 4,096-item
    /// allowance minus whatever the Engine already holds, computed by the
    /// caller. The cap is enforced here, structurally: no caller quantum
    /// can stage past it, and the outcome reports whether the allowance
    /// (rather than the quantum or an empty ring) stopped the move.
    pub(crate) fn stage(
        &mut self,
        quantum: usize,
        shared_cap: usize,
        mut next: impl FnMut() -> Option<events::DiscoveryItem>,
    ) -> DiscoveryStageOutcome {
        let mut staged = 0;
        while staged < quantum && self.items.len() < shared_cap.min(Self::CAPACITY) {
            let Some(item) = next() else {
                return DiscoveryStageOutcome {
                    staged,
                    capacity_blocked: false,
                };
            };
            self.items.push_back(item);
            staged += 1;
        }
        let capacity_blocked =
            staged < quantum && self.items.len() >= shared_cap.min(Self::CAPACITY);
        DiscoveryStageOutcome {
            staged,
            capacity_blocked,
        }
    }

    /// Whether the idle wait polls DISCOVERY beside EVENTS: only while
    /// the staged FIFO plus what the Engine still holds leaves room under
    /// the shared allowance. A snapshot per call: staging past the call
    /// flips the next decision, never the returned set.
    pub(crate) fn poll_discovery(staged_len: usize, engine_held: usize) -> bool {
        staged_len.saturating_add(engine_held) < Self::CAPACITY
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

/// Both lazy Session routes create and wire the one retained consumer here.
pub(crate) fn ensure_pid_discovery_consumer_with<S: events::RecordSource>(
    consumer: &mut Option<events::DiscoveryDrain<S>>,
    tap: Option<&PidLifecycleTap>,
    create: impl FnOnce() -> Result<events::DiscoveryDrain<S>>,
) -> Result<bool> {
    let created = consumer.is_none();
    if created {
        let mut drain = create().inspect_err(|_| {
            if let Some(tap) = tap {
                tap.observe_failure();
            }
        })?;
        if let Some(tap) = tap {
            drain
                .attach_pid_lifecycle_tap(tap.clone())
                .map_err(|reason| anyhow!("PID lifecycle consumer: {reason:?}"))?;
        }
        *consumer = Some(drain);
    } else if let Some(tap) = tap {
        consumer
            .as_mut()
            .expect("checked consumer")
            .attach_pid_lifecycle_tap(tap.clone())
            .map_err(|reason| anyhow!("PID lifecycle consumer: {reason:?}"))?;
    }
    Ok(created)
}

fn invalidate_pid_session(pairs: &mut pid_continuity::PairBook, tap: Option<&PidLifecycleTap>) {
    pairs.invalidate_all();
    if let Some(tap) = tap {
        tap.invalidate_terminal();
    }
}

/// The terminal collection's staged branch must refuse continuity before its
/// early return, just as the raw bounded poll does before touching the ring.
pub(crate) fn collect_staged_discovery_to_position<S: events::BoundedRecordSource>(
    staged: &mut DiscoveryStage,
    consumer: &mut events::DiscoveryDrain<S>,
    stop: usize,
    quantum: usize,
) -> Result<(Vec<p11scope_ebpf_common::DiscoveryRecord>, u64, bool, bool)> {
    consumer.invalidate_pid_lifecycle_terminal();
    let mut records = Vec::new();
    let mut malformed = 0u64;
    let mut left = quantum;
    while left > 0 {
        let Some(item) = staged.pop() else {
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
    let (post_q_record, backlog) =
        events::poll_discovery_to_position(consumer, stop, Some(left), |item| {
            match item {
                events::DiscoveryItem::Record(record) => records.push(record),
                events::DiscoveryItem::Malformed => malformed = malformed.saturating_add(1),
            }
            std::ops::ControlFlow::Continue(())
        })?;
    Ok((records, malformed, post_q_record, backlog))
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
    validate_program_inventory_with_roots(ebpf, unsafe_enabled, StaticRoots::Detailed)
}

fn validate_program_inventory_with_roots(
    ebpf: &Ebpf,
    unsafe_enabled: bool,
    roots: StaticRoots,
) -> Result<()> {
    let mut expected = expected_programs(unsafe_enabled);
    // The continuity hooks are present in every Detailed object but load
    // before deferred freezes, optionally (`InstanceTracking::prepare`).
    expected.extend(INSTANCE_PROGRAMS.iter().map(|(program, _)| *program));
    expected.insert("p11_image_query");
    expected.extend(selected_detailed::PROGRAMS);
    if roots == StaticRoots::CounterBanks {
        expected.extend(counter_banks::PROGRAMS);
    }
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
    PublishObjects,
    FreezePublished,
    SelectScope,
    LoadProgram(&'static str),
    LoadImagePrograms,
    LoadCounterPrograms,
    FreezeDeferred(&'static str),
    PublishTailCalls,
    PrepareEventsDomain,
}

// BTF and object creation are prerequisites. This is the single loaded-object
// preparation order used by startup; activation cannot bypass a preparation failure.
fn prepare_session_with(
    object_has_unsafe: bool,
    roots: StaticRoots,
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
        PublishObjects,
        FreezePublished,
        SelectScope,
    ] {
        operation(step)?;
    }
    for name in expected_programs(object_has_unsafe) {
        operation(LoadProgram(name))?;
    }
    operation(LoadImagePrograms)?;
    if roots == StaticRoots::CounterBanks {
        operation(LoadCounterPrograms)?;
    }
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

fn read_pid_health_with(
    ebpf: &Ebpf,
    health: &mut pid_continuity::OwnerHealth,
    prepared_owner_limit: u64,
    tap: &PidLifecycleTap,
) -> std::result::Result<u64, PidContinuityRefusal> {
    let owner = (|| -> Result<ThreadOwnerControl> {
        let control: Array<_, ThreadOwnerControl> =
            Array::try_from(ebpf.map("OWNER_CTL").context("OWNER_CTL map")?)?;
        Ok(control.get(&0, 0)?)
    })()
    .map_err(|_| PidContinuityRefusal::Unavailable);
    let loss = (|| -> Result<u64> {
        let counters: PerCpuArray<_, u64> =
            PerCpuArray::try_from(ebpf.map("COUNTERS").context("COUNTERS map")?)?;
        pid_continuity::checked_discovery_loss(
            counters
                .get(&DISCOVERY_COUNTER_RING_LOSS, 0)?
                .iter()
                .copied(),
        )
        .map_err(|reason| anyhow!("PID continuity loss: {reason:?}"))
    })()
    .map_err(|_| PidContinuityRefusal::Loss);
    health.check(owner, loss, prepared_owner_limit, tap)
}

impl Session {
    #[cfg(feature = "h6-reexec-diagnostic")]
    pub(crate) fn reexec_diagnostic(&self) -> Option<reexec_diagnostic::Diagnostic> {
        self.reexec_diagnostic.clone()
    }

    pub(crate) const fn capture_policy(&self) -> CapturePolicy {
        self.policy
    }

    #[allow(dead_code)] // Staged for the Session-bound complete counter reader.
    pub(crate) const fn counter_collection_generation(&self) -> NonZeroU64 {
        self.counter_collection_generation
    }

    /// The session's stop-gate mapping.
    pub(crate) fn stop_gate(&self) -> &StopGate {
        &self.stop_gate
    }

    /// Observe this Session's actual producer Q without consuming either
    /// retained ring. A pending result retains all Session ownership.
    #[allow(dead_code)] // No machine/terminal activation in this slice.
    pub(crate) fn observe_collected_finish_q(
        &mut self,
        expected: &SessionDrainProducers,
        grant: Option<&crate::semantics_objects::journal::SessionDrainGrant>,
    ) -> Result<Option<CollectedFinishQ>> {
        let producers = self
            .drain_producers()
            .context("collected Finish Q has no retained native domain")?;
        {
            let owner = CollectedFinishQOwner {
                gate: &self.stop_gate,
                producers: &producers,
                discovery: &self.discovery_domain,
                detach: &self.producer_detach,
            };
            validate_collected_finish_q_owner(&owner, expected, grant)?;
            if !owner.gate.quiescent() {
                return Ok(None);
            }
        }
        self.ensure_events_consumer()?;
        self.ensure_discovery_consumer()?;
        let events = self
            .events_consumer
            .as_ref()
            .context("retained EVENTS consumer vanished during Q observation")?;
        let discovery = self
            .discovery_consumer
            .as_ref()
            .context("retained DISCOVERY consumer vanished during Q observation")?;
        observe_collected_finish_q_with(
            CollectedFinishQOwner {
                gate: &self.stop_gate,
                producers: &producers,
                discovery: &self.discovery_domain,
                detach: &self.producer_detach,
            },
            expected,
            grant,
            || {
                events
                    .consumption_cut()
                    .map_err(|reason| anyhow!("collected Finish EVENTS cut refused: {reason:?}"))
            },
            || Ok(events::discovery_drain_positions(discovery)),
        )
    }

    /// Same retained Session and current native Q only. This is not evidence
    /// of completed drain, clean prefix, process death or detach permission.
    #[allow(dead_code)] // Pending-at-Q forwarding remains inactive in the ordinary driver.
    pub(crate) fn matches_collected_finish_q(&self, q: &CollectedFinishQ) -> bool {
        matches!(self.producer_detach, OwnedProducerDetach::NotStarted)
            && self.stop_gate.quiescent()
            && self
                .drain_producers()
                .as_ref()
                .is_some_and(|producers| q.matches_owner(producers, &self.discovery_domain))
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
        Self::start_with_selected(
            plan,
            scope,
            objects,
            policy,
            pause_generation,
            ring_bytes,
            owned_child,
            selection,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn start_with_selected(
        plan: &AttachPlan,
        scope: &Scope,
        objects: &PinnedObjects,
        policy: CapturePolicy,
        pause_generation: Option<OwnedPauseGeneration>,
        ring_bytes: Option<u32>,
        owned_child: Option<&OwnedChild>,
        selection: BackendSelection,
        selected: Option<&crate::process::PidPin>,
    ) -> Result<Self> {
        // Raise before the first link: every return/entry pair burns fds
        // against RLIMIT_NOFILE, and no tracker (the previous raise site)
        // exists yet at attach time. A 1024 soft limit dies near slot 256.
        let _ = crate::process::raise_nofile();
        let pause_key = pause_key_for(scope, pause_generation.as_ref())?;
        let SessionBackend { backend, fallback } = select_session_backend(
            selection,
            matches!(scope, Scope::Pid(_)) || selected.is_some(),
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
            selected,
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
                    selected,
                )
                .map(|session| (session, Some(reason)))
            }
            Err(error) => Err(error),
        };
        let (mut session, fallback) = started?;
        session.selection = selection;
        session.backend_fallback = fallback;
        #[cfg(feature = "h6-reexec-diagnostic")]
        {
            session.reexec_diagnostic = reexec_diagnostic::Diagnostic::selected(
                matches!(scope, Scope::Pid(_)),
                selection == BackendSelection::Singles,
            );
        }
        Ok(session)
    }

    /// The receipt is minted from this new Session's maps and retained links;
    /// the caller supplies only the coordinator's move-only accepted subset.
    pub(crate) fn start_attested(
        subset: crate::inventory_semantics::AttestedSubset,
        scope: &Scope,
        selection: BackendSelection,
    ) -> Result<(Self, AttachedSemanticSet)> {
        let mut session = Self::start(
            subset.plan(),
            scope,
            subset.pins(),
            CapturePolicy::Allowlisted,
            None,
            None,
            None,
            selection,
        )?;
        // H7 slice D: freeze the receipt-bound object rows before minting
        // the receipt. A readback disagreement refuses the attested
        // session; without verified rows no 608-byte record decodes.
        session.object_decode = Some(freeze_object_decode_table(&session.ebpf)?);
        let domain = session
            .native_domain()
            .context("Detailed image domain unavailable")?;
        let attached = seal_attached_subset_native(
            &session.ebpf,
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
        current_static_sides_from(&self.links)
    }

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
        selected: Option<&crate::process::PidPin>,
    ) -> Result<Self> {
        if !objects.check_unchanged().map_err(anyhow::Error::msg)? {
            bail!(
                "a pinned provider object changed before attach; refusing to observe changed bytes"
            );
        }
        let mut session = Self::start_inner(
            scope,
            policy,
            pause_key,
            ring_bytes,
            owned_child,
            backend,
            selected,
        )
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
        // The Engine holds nothing yet; whatever does not fit waits in the
        // kernel ring for the next staging call after the first batch.
        session.stage_discovery(crate::discovery::engine::LIVE_DISCOVERY_DRAIN_QUANTUM, 0)?;
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
            None,
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
        selected: Option<&crate::process::PidPin>,
    ) -> Result<Self> {
        let (mut session, prepared_instance) = Self::prepare_inner_unlinked(
            scope,
            policy,
            pause_key,
            ring_bytes,
            owned_child,
            backend,
            selected,
        )?;
        session.links = activate_after_preparation_with(Ok(()), || {
            attach_lifecycle_with(
                &mut session.ebpf,
                Self::attach_lifecycle_program,
                |ebpf, _, link| detach_registered_link(ebpf, link),
            )
        })?;
        // Preserve ordinary activation order: mandatory lifecycle first,
        // then image continuity, and endpoint attachment only afterwards.
        session.trace_coverage =
            detailed_identity::TraceCoverage::after_activation(scope, monotonic_ns());
        session.instance = InstanceTracking::start(
            &mut session.ebpf,
            &session.image_coverage,
            prepared_instance,
        );
        Ok(session)
    }

    fn attach_lifecycle_program(ebpf: &mut Ebpf, program: &'static str) -> Result<RegisteredLink> {
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
    }

    fn prepare_inner_unlinked(
        scope: &Scope,
        policy: CapturePolicy,
        pause_key: Option<PauseKey>,
        ring_bytes: Option<u32>,
        owned_child: Option<&OwnedChild>,
        backend: AttachBackend,
        selected: Option<&crate::process::PidPin>,
    ) -> Result<(Self, instance::PreparedInstanceTracking)> {
        Self::prepare_inner_unlinked_with_object(
            scope,
            policy,
            pause_key,
            ring_bytes,
            owned_child,
            backend,
            selected,
            None,
        )
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "private common preparation adds a closed unselected object profile"
    )]
    fn prepare_inner_unlinked_with_object(
        scope: &Scope,
        policy: CapturePolicy,
        pause_key: Option<PauseKey>,
        ring_bytes: Option<u32>,
        owned_child: Option<&OwnedChild>,
        backend: AttachBackend,
        selected: Option<&crate::process::PidPin>,
        counter: Option<counter_banks::CounterPreparation<'_>>,
    ) -> Result<(Self, instance::PreparedInstanceTracking)> {
        // The bytes rule before anything loads or attaches: a stale or
        // mismatched embedded object refuses here with both values named.
        let flavor = checked_embedded_flavor()?;
        if policy.uses_unsafe_decoders() && !flavor.unsafe_present {
            bail!("unsafe-unvalidated-metadata policy is absent from this eBPF object");
        }
        let counter_collection_generation = counter_generation::allocate()?;
        // `--ring-bytes` resizes the EVENTS ringbuf at load (aya rounds to a
        // page-sized power of two like libbpf); omission resolves to the
        // baked-in default, which is a no-op override of the ELF value.
        // The required vmlinux BTF parse populates the process-wide
        // host_btf cache, so no budgeted job tick pays the cold sysfs
        // re-read, parse, or selector scan.
        let host =
            host_btf::shared().context("loading required vmlinux BTF for typed task_newtask")?;
        let domain = if policy.wants_instance_hooks() {
            Some(capture::NativeDomainId::try_mint()?)
        } else {
            None
        };
        let roots = if counter.is_some() {
            StaticRoots::CounterBanks
        } else {
            StaticRoots::Detailed
        };
        let mut ebpf = load_capture_object_bytes_with_images(
            host.btf(),
            crate::run::resolve_ring_bytes(ring_bytes),
            discovery_ring_bytes(scope),
            policy.wants_instance_hooks(),
            counter
                .as_ref()
                .map_or(crate::EBPF_OBJECT, |prepared| prepared.object),
        )
        .context("loading BPF object with required task storage")?;
        let native_selection =
            selected_detailed::NativeSelection::publish(&mut ebpf, scope, selected)?;
        let object_has_unsafe = flavor.unsafe_present;
        let unsafe_enabled = object_has_unsafe && policy.uses_unsafe_decoders();
        let generation_token = pause_key.map(|key| key.generation_token);
        let mut uprobe_scope = UProbeScope::AllProcesses;
        let mut stop_gate = None;
        let mut prepared_domain = None;
        let mut prepared_discovery_domain = None;
        let mut root_seed = None;
        let mut image_query = None;
        let mut prepared_instance = None;
        let mut prepared_owner_limit = None;
        let preparation = prepare_session_with(object_has_unsafe, roots, |step| {
            match step {
                SessionPreparation::ValidatePolicy => {
                    validate_policy_maps(&ebpf, object_has_unsafe)
                        .context("validating exact policy-map metadata")?;
                }
                SessionPreparation::ValidateRuntime => {
                    validate_runtime_maps(&ebpf, discovery_ring_bytes(scope))
                        .context("validating live-discovery runtime maps")?;
                    image_query::prepare_maps(&ebpf, policy.wants_instance_hooks())?;
                    instance::prepare_marker_control(&ebpf, roots)?;
                    selected_detailed::validate_maps(&ebpf)?;
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
                    (if roots == StaticRoots::Detailed {
                        validate_program_inventory(&ebpf, object_has_unsafe)
                    } else {
                        validate_program_inventory_with_roots(&ebpf, object_has_unsafe, roots)
                    })
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
                    // START metadata is immutable. Retain the same validated
                    // capacity-derived limit initialized and read back above.
                    prepared_owner_limit = Some(owner_limit_from_start(&ebpf)?);
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
                SessionPreparation::PublishObjects => {
                    publish_object_custody_maps(&mut ebpf)
                        .context("publishing OBJECT_DESCRIPTORS")?;
                }
                SessionPreparation::FreezePublished => {
                    freeze_published_maps(&ebpf).context("freezing published policy maps")?;
                }
                SessionPreparation::SelectScope => {
                    uprobe_scope = if let Some(pin) = selected {
                        UProbeScope::OneProcess(
                            NonZeroU32::new(pin.pid()).context("selected pid must be nonzero")?,
                        )
                    } else {
                        match scope {
                            Scope::Pid(pid) => UProbeScope::OneProcess(
                                std::num::NonZeroU32::new(*pid).context("pid must be non-zero")?,
                            ),
                            // Cgroup and system scoping are enforced in BPF, so the
                            // probe itself is process-wide and the CONFIG bit decides.
                            Scope::Cgroup { .. } | Scope::System => UProbeScope::AllProcesses,
                        }
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
                        prog.load("task_newtask", host.btf())
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
                    if selected.is_some() {
                        selected_detailed::load_bootstrap(&mut ebpf, host.btf())?;
                    }
                    let query_refusal = match domain {
                        Some(domain) => {
                            match image_query::ImageQueryOwner::load(
                                &mut ebpf,
                                host.btf(),
                                domain,
                                host.supports_pidfd_iter_selector(),
                            ) {
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
                        host.btf(),
                        policy,
                        query_refusal,
                    ));
                }
                SessionPreparation::LoadCounterPrograms => {
                    counter
                        .as_ref()
                        .context("counter preparation requires its selected profile")?
                        .validate_and_load(&mut ebpf, backend)?;
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
        // No producer has been attached yet. A selected attempt takes custody
        // of this complete owner before attaching its first lifecycle link.
        preparation?;
        let events_domain = prepared_domain.expect("preparation established the events domain");
        let discovery_domain =
            prepared_discovery_domain.expect("preparation established the discovery domain");
        let image_coverage = image_query::CoverageControl::new(&ebpf)?;

        let pid_lifecycle = match uprobe_scope {
            UProbeScope::OneProcess(pid) => {
                Some(PidLifecycleTap::new(pid, discovery_domain.clone()))
            }
            UProbeScope::AllProcesses | UProbeScope::CallingProcess => None,
        };

        Ok((
            Self {
                stop_gate: stop_gate.expect("preparation established the stop gate"),
                native_selection,
                image_coverage,
                image_query,
                ebpf,
                events_domain,
                events_consumer: None,
                discovery_domain,
                trace_coverage: None,
                trace_proof: None,
                discovery_consumer: None,
                discovery_staged: DiscoveryStage::default(),
                root_seed,
                attach_failures: vec![],
                detach_failures: vec![],
                producers_detached: false,
                detach_wall_ms: 0,
                attach_mono_ns: None,
                counter_collection_generation,
                successful_static: BTreeSet::new(),
                dynamic_attach_evidence: DynamicAttachEvidence::default(),
                policy,
                embedded_flavor: flavor,
                backend,
                selection: BackendSelection::Auto,
                backend_fallback: None,
                uprobe_scope,
                pause_key,
                lifecycle_tracking_unavailable: None,
                process_creation_tracking_unavailable: None,
                retained_static: BTreeMap::new(),
                pid_pairs: pid_continuity::PairBook::default(),
                global_retirements: global_retirement::Retirements::default(),
                native_retirement: native_retirement::NativeRetirement::default(),
                deferred_group_slots: BTreeSet::new(),
                submitted_terminal_slots: BTreeSet::new(),
                pid_health: pid_continuity::OwnerHealth::default(),
                prepared_owner_limit: prepared_owner_limit
                    .expect("identity preparation retained exact owner limit"),
                pid_lifecycle,
                links: Vec::new(),
                instance: InstanceTracking::default(),
                cleanup_worker: Some(CleanupWorker::pre_start()),
                producer_detach: OwnedProducerDetach::NotStarted,
                native_completion_mint: NativeCompletionMint::default(),
                object_decode: None,
                #[cfg(feature = "h6-reexec-diagnostic")]
                reexec_diagnostic: None,
                counter_banks: counter.map(|prepared| prepared.banks),
            },
            prepared_instance.expect("preparation established image program load result"),
        ))
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

    fn read_pid_health(&mut self) -> std::result::Result<u64, PidContinuityRefusal> {
        let tap = self
            .pid_lifecycle
            .as_ref()
            .ok_or(PidContinuityRefusal::Unavailable)?;
        read_pid_health_with(
            &self.ebpf,
            &mut self.pid_health,
            self.prepared_owner_limit,
            tap,
        )
    }

    pub(crate) fn mutation_stopped(&self) -> bool {
        self.stop_gate.stop_requested()
            || self.producer_detach.started()
            || self.producers_detached
            || !self.detach_failures.is_empty()
            || self.pid_health.terminal()
            || self
                .pid_lifecycle
                .as_ref()
                .is_some_and(|tap| tap.facts().is_err())
    }

    fn pid_attach_baseline(&mut self) -> Option<pid_continuity::AttachBaseline> {
        if !matches!(self.uprobe_scope, UProbeScope::OneProcess(_)) || self.mutation_stopped() {
            return None;
        }
        let loss = self.read_pid_health();
        let fault = self
            .pid_lifecycle
            .as_ref()
            .and_then(|tap| tap.facts().ok())
            .map(|facts| facts.fault_serial);
        let baseline = self.pid_pairs.prepare_baseline(loss, fault);
        if baseline.is_none()
            && let Some(tap) = &self.pid_lifecycle
        {
            tap.observe_failure();
        }
        baseline
    }

    pub(crate) fn physical_gap_summary(&self) -> PhysicalGapSummary {
        global_retirement::merge_summaries(
            self.pid_pairs.gap_summary(),
            self.global_retirements.summary(),
        )
    }

    pub(crate) fn prepare_ended_pid_retirement(
        &self,
        view: &crate::process::ProcessView,
        slots: &[Slot],
    ) -> Option<EndedPidRetirement> {
        if self.mutation_stopped() {
            return None;
        }
        EndedPidRetirement::prepare(
            &self.discovery_domain,
            self.uprobe_scope,
            view,
            slots,
            &self.links,
            &self.retained_static,
        )
    }

    pub(crate) fn bind_exec(
        &self,
        view: &crate::process::ProcessView,
        serial: u64,
        record: &p11scope_ebpf_common::DiscoveryRecord,
    ) -> Option<ExecBinding> {
        if self.mutation_stopped()
            || !matches!(self.uprobe_scope, UProbeScope::OneProcess(pid) if pid.get() == view.pid())
        {
            return None;
        }
        ExecBinding::bind(
            self.pid_lifecycle.as_ref()?,
            &self.discovery_domain,
            view,
            serial,
            record,
        )
    }

    pub(crate) fn prepare_preservation(
        &mut self,
        binding: &ExecBinding,
        view: &crate::process::ProcessView,
        serial: u64,
        slots: &[Slot],
        ordinary: &[Slot],
        objects: &PinnedObjects,
    ) -> Option<PreservationReceipt> {
        if self.mutation_stopped() {
            reexec_diagnostic::observe!(self, |diag| {
                diag.note(
                    DiagnosticPhase::Rearm,
                    DiagnosticOutcome::Stopped,
                    [None; 4],
                );
            });
            return None;
        }
        let loss = match self.read_pid_health() {
            Ok(loss) => loss,
            Err(_) => {
                reexec_diagnostic::observe!(self, |diag| {
                    diag.note(
                        DiagnosticPhase::Rearm,
                        DiagnosticOutcome::NoHealth,
                        [None; 4],
                    );
                });
                return None;
            }
        };
        let sides = self.current_static_sides();
        let pairs = pid_continuity::CurrentPairs {
            book: &self.pid_pairs,
            links: &self.links,
            sides: &sides,
            retained: &self.retained_static,
        };
        let Some(tap) = self.pid_lifecycle.as_ref() else {
            reexec_diagnostic::observe!(self, |diag| {
                diag.note(
                    DiagnosticPhase::Rearm,
                    DiagnosticOutcome::Unavailable,
                    [None; 4],
                );
            });
            return None;
        };
        let Some(receipt) = pairs.prepare(
            binding,
            tap,
            &self.discovery_domain,
            view,
            serial,
            slots,
            ordinary,
            objects,
            loss,
        ) else {
            reexec_diagnostic::observe!(self, |diag| {
                diag.note(
                    DiagnosticPhase::Rearm,
                    DiagnosticOutcome::NoPairs,
                    [
                        Some(slots.len() as u64),
                        Some(ordinary.len() as u64),
                        None,
                        None,
                    ],
                );
            });
            return None;
        };
        let valid = pairs.validate(
            &receipt,
            binding,
            tap,
            &self.discovery_domain,
            view,
            serial,
            objects,
            loss,
            || {
                self.discovery_consumer
                    .as_ref()
                    .map(events::discovery_drain_positions)
            },
        );
        reexec_diagnostic::observe!(self, |diag| {
            diag.note(
                DiagnosticPhase::Rearm,
                if valid {
                    DiagnosticOutcome::Preserved
                } else {
                    DiagnosticOutcome::NoValidation
                },
                [Some(slots.len() as u64), None, None, None],
            );
        });
        valid.then_some(receipt)
    }

    pub(crate) fn prepare_completed_rearm(
        &mut self,
        binding: &ExecBinding,
        view: &crate::process::ProcessView,
        serial: u64,
        slots: &[Slot],
        ordinary: &[Slot],
        objects: &PinnedObjects,
    ) -> Option<CompletedRearmReceipt> {
        if self.mutation_stopped() {
            return None;
        }
        let loss = self.read_pid_health().ok()?;
        let tap = self.pid_lifecycle.as_ref()?;
        let sides = self.current_static_sides();
        let pairs = pid_continuity::CurrentPairs {
            book: &self.pid_pairs,
            links: &self.links,
            sides: &sides,
            retained: &self.retained_static,
        };
        let receipt = pairs.prepare_completed_rearm(
            binding,
            tap,
            &self.discovery_domain,
            view,
            serial,
            slots,
            ordinary,
            objects,
            loss,
        )?;
        let health = &mut self.pid_health;
        let ebpf = &self.ebpf;
        let limit = self.prepared_owner_limit;
        let consumer = &self.discovery_consumer;
        let valid = pairs.validate_completed_rearm(
            &receipt,
            binding,
            tap,
            &self.discovery_domain,
            view,
            serial,
            objects,
            || {
                let loss = read_pid_health_with(ebpf, health, limit, tap).ok()?;
                Some((
                    loss,
                    consumer.as_ref().map(events::discovery_drain_positions)?,
                ))
            },
        );
        (valid && !self.mutation_stopped()).then_some(receipt)
    }

    pub(crate) fn validate_completed_rearm(
        &mut self,
        receipt: &CompletedRearmReceipt,
        binding: &ExecBinding,
        view: &crate::process::ProcessView,
        serial: u64,
        objects: &PinnedObjects,
    ) -> bool {
        if self.mutation_stopped() {
            return false;
        }
        let Some(tap) = self.pid_lifecycle.as_ref() else {
            return false;
        };
        let sides = self.current_static_sides();
        let pairs = pid_continuity::CurrentPairs {
            book: &self.pid_pairs,
            links: &self.links,
            sides: &sides,
            retained: &self.retained_static,
        };
        let health = &mut self.pid_health;
        let ebpf = &self.ebpf;
        let limit = self.prepared_owner_limit;
        let consumer = &self.discovery_consumer;
        pairs.validate_completed_rearm(
            receipt,
            binding,
            tap,
            &self.discovery_domain,
            view,
            serial,
            objects,
            || {
                let loss = read_pid_health_with(ebpf, health, limit, tap).ok()?;
                Some((
                    loss,
                    consumer.as_ref().map(events::discovery_drain_positions)?,
                ))
            },
        ) && !self.mutation_stopped()
    }

    pub(crate) fn validate_preservation(
        &mut self,
        receipt: &PreservationReceipt,
        binding: &ExecBinding,
        view: &crate::process::ProcessView,
        serial: u64,
        objects: &PinnedObjects,
    ) -> bool {
        if self.mutation_stopped() {
            reexec_diagnostic::observe!(self, |diag| {
                diag.note(
                    DiagnosticPhase::Preflight,
                    DiagnosticOutcome::Stopped,
                    [None; 4],
                );
            });
            return false;
        }
        let Ok(loss) = self.read_pid_health() else {
            reexec_diagnostic::observe!(self, |diag| {
                diag.note(
                    DiagnosticPhase::Preflight,
                    DiagnosticOutcome::NoHealth,
                    [None; 4],
                );
            });
            return false;
        };
        let Some(tap) = self.pid_lifecycle.as_ref() else {
            reexec_diagnostic::observe!(self, |diag| {
                diag.note(
                    DiagnosticPhase::Preflight,
                    DiagnosticOutcome::Unavailable,
                    [None; 4],
                );
            });
            return false;
        };
        let sides = self.current_static_sides();
        let pairs = pid_continuity::CurrentPairs {
            book: &self.pid_pairs,
            links: &self.links,
            sides: &sides,
            retained: &self.retained_static,
        };
        let valid = pairs.validate(
            receipt,
            binding,
            tap,
            &self.discovery_domain,
            view,
            serial,
            objects,
            loss,
            || {
                self.discovery_consumer
                    .as_ref()
                    .map(events::discovery_drain_positions)
            },
        );
        reexec_diagnostic::observe!(self, |diag| {
            diag.note(
                DiagnosticPhase::Preflight,
                if valid {
                    DiagnosticOutcome::Preserved
                } else {
                    DiagnosticOutcome::NoValidation
                },
                [None; 4],
            );
        });
        valid
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
        stopped_attachment_admission(self.mutation_stopped(), "dynamic")
            .map_err(DynamicLoaderAttachFailure::Registry)?;
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
        stopped_attachment_admission(self.mutation_stopped(), "dynamic")?;
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

    pub(crate) fn has_dynamic_link(
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
        if self.native_retirement.collected_blocking() {
            // No snapshot/copy or false acknowledgement of a refused detach.
            return (Vec::new(), true);
        }
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
        if self.native_retirement.collected_blocking() && targets.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        if self
            .counter_banks
            .as_ref()
            .is_some_and(|banks| !banks.permits_link_stage(targets))
        {
            bail!("private counter links require their exact inactive bank transaction");
        }
        let mut requested = BTreeSet::new();
        if let Some(slot) = targets.iter().find(|slot| !requested.insert(slot.index)) {
            bail!("slot {} was requested for attachment twice", slot.index);
        }
        if let Some(slot) = targets.iter().find(|slot| self.has_slot_link(slot.index)) {
            bail!("slot {} already has an owned probe link", slot.index);
        }
        if !targets.is_empty() && self.mutation_stopped() {
            bail!("static attachment refused while Session is stopping or detached");
        }
        if !targets.is_empty() && self.native_retirement.blocking() {
            bail!(
                "static attachment refused while old global native ownership is pending or uncertain"
            );
        }
        if !targets.is_empty() && !self.deferred_group_slots.is_empty() {
            bail!("static attachment refused while a collected group deferral owns removals");
        }
        self.pid_pairs.retarget_gap(targets, objects);
        self.global_retirements.select(targets, objects);
        attachment_admission(&self.detach_failures, !targets.is_empty())?;
        if targets.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
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
        let held_objects: BTreeMap<_, _> = targets
            .iter()
            .map(|slot| slot.object)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(|object| (object, objects.retain_inventory_target(object).ok()))
            .collect();
        let prepared_targets: Vec<_> = targets
            .iter()
            .map(|slot| {
                let (path, abi) = &attach_targets[&slot.index];
                RetainedStaticTarget {
                    slot: slot.clone(),
                    path: path.clone(),
                    abi: *abi,
                    held: held_objects
                        .get(&slot.object)
                        .and_then(Option::as_ref)
                        .map(|target| target.share()),
                }
            })
            .collect();
        if self.native_selection.is_some() || self.counter_banks.is_some() {
            // Selected failure cleanup must retain the actual provider closure
            // even if the first endpoint side or a later multi leaf fails.
            for target in &prepared_targets {
                if target.held.is_none() {
                    bail!("selected provider target custody unavailable before attachment");
                }
            }
            for target in &prepared_targets {
                self.retained_static
                    .insert(target.slot.index, target.clone());
            }
        }
        let continuity_baseline = static_attachment_baseline_with(
            self,
            Session::pid_attach_baseline,
            Session::mutation_stopped,
        )?;
        // Ordering I1: watched-file keys and SLOT_FILE before any link.
        self.instance
            .prepare_targets(&mut self.ebpf, targets, objects);
        let scope = self.uprobe_scope;
        let roots = if self.counter_banks.is_some() {
            StaticRoots::CounterBanks
        } else {
            StaticRoots::Detailed
        };
        #[cfg(feature = "h6-reexec-diagnostic")]
        let diagnostic = self.reexec_diagnostic();
        let outcome = if self.backend == AttachBackend::Multi {
            self.attach_targets_multi(targets, &attach_targets, roots)?
        } else {
            let ebpf = &mut self.ebpf;
            let links = &mut self.links;
            let pairs = &mut self.pid_pairs;
            attach_targets_observed_with_roots(
                targets,
                self.policy,
                self.embedded_flavor.unsafe_present,
                roots,
                |slot| {
                    Ok(attach_targets
                        .get(&slot.index)
                        .expect("every selected target has retained pinned facts")
                        .1)
                },
                |program, slot, point| {
                    let prepared =
                        (|| -> Result<pid_continuity::NativeAttempt<(), anyhow::Error>> {
                            let path = &attach_targets
                                .get(&slot.index)
                                .expect("every selected target has retained pinned facts")
                                .0;
                            let prog: &mut UProbe = ebpf
                                .program_mut(program)
                                .with_context(|| format!("program {program} missing from object"))?
                                .try_into()?;
                            #[cfg(feature = "h6-reexec-diagnostic")]
                            let diagnostic_span = diagnostic
                                .as_ref()
                                .filter(|diag| diag.active())
                                .map(|diag| {
                                    diag.begin(
                                        if program == "p11_return" {
                                            DiagnosticPhase::NativeReturn
                                        } else {
                                            DiagnosticPhase::NativeEntry
                                        },
                                        [
                                            Some(1),
                                            Some(u64::from(
                                                slot.names.iter().any(|name| name == "C_GetInfo"),
                                            )),
                                            None,
                                            None,
                                        ],
                                    )
                                });
                            let attempt = pid_continuity::NativeAttempt::run(
                                pid_continuity::comparable_monotonic_ns,
                                || prog.attach([point], path, scope),
                            );
                            #[cfg(feature = "h6-reexec-diagnostic")]
                            if let Some(span) = diagnostic_span {
                                span.finish_result(&attempt.result);
                            }
                            let result = match attempt.result {
                                Ok(id) => {
                                    links.push(RegisteredLink::UProbe {
                                        program,
                                        slot: slot.index,
                                        id,
                                        registration: pairs.register(),
                                    });
                                    Ok(())
                                }
                                Err(error) => Err(static_attach_error(program, slot, error)),
                            };
                            Ok(pid_continuity::NativeAttempt {
                                started_ns: attempt.started_ns,
                                result,
                            })
                        })();
                    prepared.unwrap_or_else(pid_continuity::NativeAttempt::not_attempted)
                },
                |_| monotonic_ns(),
            )?
        };
        let AttachOutcome {
            successful,
            failures,
            completed,
            continuity_rounds,
            exhausted: _,
        } = outcome;
        retain_from_successful(
            &mut self.retained_static,
            targets,
            &attach_targets,
            &successful,
        );
        for target in prepared_targets {
            if let Some(retained) = self.retained_static.get_mut(&target.slot.index) {
                retained.held = target.held;
            }
        }
        let current_sides = self.current_static_sides();
        self.pid_pairs.seal(
            &continuity_rounds,
            continuity_baseline,
            self.pid_lifecycle
                .as_ref()
                .and_then(|tap| tap.facts().ok())
                .map(|facts| facts.fault_serial),
            &self.links,
            &current_sides,
            &self.retained_static,
            pid_continuity::comparable_monotonic_ns,
        );
        self.global_retirements.seal(
            &continuity_rounds,
            &self.links,
            &current_sides,
            &self.retained_static,
            pid_continuity::comparable_monotonic_ns,
        );
        self.successful_static.extend(successful);
        let failed: Vec<_> = failures.iter().map(|(slot, _)| *slot).collect();
        self.attach_failures.extend(failures);
        reexec_diagnostic::observe!(self, |diag| {
            let sides = self.current_static_sides();
            let paired = self
                .retained_static
                .keys()
                .filter(|slot| {
                    sides.contains(&(**slot, ProbeSide::Entry))
                        && sides.contains(&(**slot, ProbeSide::Return))
                })
                .count();
            diag.note(
                DiagnosticPhase::AttachState,
                DiagnosticOutcome::Ok,
                [
                    Some(targets.len() as u64),
                    Some(failed.len() as u64),
                    Some(completed.len() as u64),
                    Some(paired as u64),
                ],
            );
        });
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
        roots: StaticRoots,
    ) -> Result<AttachOutcome> {
        let groups = group_static_slots_with_roots(
            targets,
            self.policy,
            self.embedded_flavor.unsafe_present,
            attach_targets,
            roots,
        )?;
        let mut programs: BTreeSet<&'static str> =
            groups.iter().map(|group| group.entry_program).collect();
        programs.extend(groups.iter().map(|group| group.return_program));
        let mut prog_fds = BTreeMap::new();
        for program in programs {
            prog_fds.insert(program, multi_prog_fd(&mut self.ebpf, program)?);
        }
        let pid = multi_link_pid(self.uprobe_scope);
        if roots == StaticRoots::CounterBanks {
            // NativeIo checked the complete grouping/registry envelope before
            // the floor advanced. Its retained extent charge is already in
            // CounterKeepalive and survives even a confirmed clean rollback.
            reserve_counter_multi_link_capacity(&mut self.links, targets.len())
                .map_err(|_| anyhow!("private counter registry capacity refused"))?;
            let slots_by_cookie: BTreeMap<_, _> = groups
                .iter()
                .flat_map(|group| &group.members)
                .map(|member| (member.cookie, member.slot.index))
                .collect();
            let links = &mut self.links;
            let pairs = &mut self.pid_pairs;
            let (_resource_free_bundles, outcome) = attach_target_groups_observed_with(
                &groups,
                |_| monotonic_ns(),
                |program, path, slice, is_return| {
                    let prog_fd = prog_fds
                        .get(program)
                        .copied()
                        .expect("every Counts group side pre-resolved its program fd");
                    let (offsets, cookies): (Vec<u64>, Vec<u64>) = slice.iter().copied().unzip();
                    pid_continuity::NativeAttempt::run(
                        pid_continuity::comparable_monotonic_ns,
                        || {
                            retain_counter_multi_leaf(
                                links,
                                pairs,
                                program,
                                slice,
                                &slots_by_cookie,
                                || attach_group(prog_fd, pid, path, &offsets, &cookies, is_return),
                            )
                        },
                    )
                },
            )?;
            // The generic bundles carry only unit acknowledgements. Every
            // acquired FD already belongs to Session, even on a late halt.
            return Ok(outcome);
        }
        if self.native_selection.is_some() {
            let slots_by_cookie: BTreeMap<_, _> = groups
                .iter()
                .flat_map(|group| &group.members)
                .map(|member| (member.cookie, member.slot.index))
                .collect();
            let links = &mut self.links;
            let pairs = &mut self.pid_pairs;
            let (_resource_free_bundles, outcome) = attach_target_groups_observed_with(
                &groups,
                |_| monotonic_ns(),
                |program, path, slice, is_return| {
                    let prog_fd = prog_fds
                        .get(program)
                        .copied()
                        .expect("every selected group side pre-resolved its program fd");
                    let (offsets, cookies): (Vec<u64>, Vec<u64>) = slice.iter().copied().unzip();
                    let attempt = pid_continuity::NativeAttempt::run(
                        pid_continuity::comparable_monotonic_ns,
                        || attach_group(prog_fd, pid, path, &offsets, &cookies, is_return),
                    );
                    let result = selected_detailed::multi::retain_success(attempt.result, |fd| {
                        links.push(RegisteredLink::MultiUProbe {
                            program,
                            slots: slice
                                .iter()
                                .map(|(_, cookie)| slots_by_cookie[cookie])
                                .collect(),
                            fds: vec![fd],
                            registration: pairs.register(),
                        });
                    });
                    pid_continuity::NativeAttempt {
                        started_ns: attempt.started_ns,
                        result,
                    }
                },
            )?;
            // Every actual fd is already in Session. Unit bundles can be
            // dropped on any later Unsupported without losing native custody.
            return Ok(outcome);
        }
        let (bundles, outcome) = attach_target_groups_observed_with(
            &groups,
            |_| monotonic_ns(),
            |program, path, slice, is_return| {
                let prog_fd = prog_fds
                    .get(program)
                    .copied()
                    .expect("every group side pre-resolved its program fd");
                let (offsets, cookies): (Vec<u64>, Vec<u64>) = slice.iter().copied().unzip();
                pid_continuity::NativeAttempt::run(pid_continuity::comparable_monotonic_ns, || {
                    attach_group(prog_fd, pid, path, &offsets, &cookies, is_return)
                })
            },
        )?;
        publish_kept_multi_bundles(
            &mut self.links,
            &mut self.retained_static,
            bundles,
            &[],
            &mut self.pid_pairs,
        );
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
        if !replace.is_empty() && self.native_retirement.blocking() {
            bail!("replacement refused while old global native ownership is pending or uncertain");
        }
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
        let detach = self.detach_failed_slots(&failed_slots);
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
        self.detach_slots_with_ended(slots, None, false)
    }

    /// Opt-in ownership handoff for the ordinary whole-candidate consumer.
    /// Generic selective detach remains synchronous.
    pub(crate) fn begin_global_static_retirement(
        &mut self,
        slots: &[Slot],
    ) -> Result<Option<RetirementTicket>> {
        let stopped = self.mutation_stopped();
        if !matches!(self.uprobe_scope, UProbeScope::AllProcesses) || stopped {
            return Ok(None);
        }
        if self.native_retirement.blocking() {
            bail!("an earlier global native retirement is pending or uncertain");
        }
        let requested: BTreeSet<_> = slots.iter().map(|slot| slot.index).collect();
        if plan_group_rebuild(&self.links, &requested).is_some() {
            return Ok(None);
        }
        // Resolve every fallible singles program/type lookup before the gap
        // ledger or live registry can change, as the synchronous path does.
        for link in &self.links {
            if let RegisteredLink::UProbe { program, slot, .. } = link
                && requested.contains(slot)
            {
                let _: &mut UProbe = self
                    .ebpf
                    .program_mut(program)
                    .with_context(|| format!("program {program} missing before static retirement"))?
                    .try_into()?;
            }
        }
        let Some(worker) = self.cleanup_worker.as_ref() else {
            return Ok(None);
        };
        let counter_keepalive = self
            .counter_banks
            .as_ref()
            .map(|banks| Arc::clone(&banks.keepalive));
        let ebpf = &mut self.ebpf;
        self.native_retirement.begin_with(
            self.uprobe_scope,
            stopped,
            false,
            false,
            slots,
            &mut self.links,
            &mut self.retained_static,
            &mut self.pid_pairs,
            &mut self.global_retirements,
            worker,
            |link| {
                take_owned_links(ebpf, link).map(|links| {
                    links
                        .into_iter()
                        .map(|link| counter_banks::retain_link(link, counter_keepalive.as_ref()))
                        .collect()
                })
            },
            pid_continuity::comparable_monotonic_ns,
        )
    }

    pub(crate) fn poll_global_retirement(&mut self, ticket: &RetirementTicket) -> RetirementPoll {
        let Some(worker) = &self.cleanup_worker else {
            return RetirementPoll::Refused;
        };
        self.native_retirement.poll(ticket, worker)
    }

    /// Bounded collected retirement on this original stopped Session. STOP
    /// prevents fresh attachment; the exact original Q separately permits
    /// this removal-only carrier. No live-only stopped refusal is reused.
    pub(crate) fn prepare_collected_static_retirement(
        &mut self,
        q: &CollectedFinishQ,
        input: &mut Option<RetainedRetirementInput>,
        reserver: &crate::semantics_edge::resources::SemanticResourceReserver,
        work: usize,
    ) -> Result<RetirementProgress> {
        if work == 0 {
            return Ok(RetirementProgress::yielded());
        }
        // The current item alone is resolved. There is no registry-wide
        // program lookup hidden inside one preparation credit.
        if let Some(program) = self.native_retirement.program_to_validate(&self.links) {
            let _: &mut UProbe = self
                .ebpf
                .program_mut(program)
                .with_context(|| format!("program {program} missing before collected retirement"))?
                .try_into()?;
        }
        let producers = self
            .drain_producers()
            .context("collected retirement has no original producers")?;
        let events = self
            .events_consumer
            .as_ref()
            .context("collected retirement needs retained EVENTS")?;
        let discovery = self
            .discovery_consumer
            .as_ref()
            .context("collected retirement needs retained DISCOVERY")?;
        let worker = self
            .cleanup_worker
            .as_ref()
            .context("collected retirement needs its prestarted worker")?;
        self.native_retirement.prepare_collected_with(
            CollectedFinishQOwner {
                gate: &self.stop_gate,
                producers: &producers,
                discovery: &self.discovery_domain,
                detach: &self.producer_detach,
            },
            q,
            self.uprobe_scope,
            input,
            reserver,
            &self.links,
            &self.retained_static,
            &self.pid_pairs,
            worker,
            || {
                events
                    .consumption_cut()
                    .map_err(|reason| anyhow!("collected EVENTS cut refused: {reason:?}"))
            },
            || Ok(events::discovery_drain_positions(discovery)),
            work,
        )
    }

    pub(crate) fn begin_collected_static_retirement(
        &mut self,
        q: &CollectedFinishQ,
        ticket: &CollectedRetirementTicket,
        work: usize,
    ) -> Result<RetirementProgress> {
        if work == 0 {
            return Ok(RetirementProgress::yielded());
        }
        let producers = self
            .drain_producers()
            .context("collected retirement has no original producers")?;
        let events = self
            .events_consumer
            .as_ref()
            .context("collected retirement needs retained EVENTS")?;
        let discovery = self
            .discovery_consumer
            .as_ref()
            .context("collected retirement needs retained DISCOVERY")?;
        let worker = self
            .cleanup_worker
            .as_ref()
            .context("collected retirement needs its prestarted worker")?;
        let keepalive = self
            .counter_banks
            .as_ref()
            .map(|banks| Arc::clone(&banks.keepalive));
        let ebpf = &mut self.ebpf;
        self.native_retirement.begin_collected_with(
            CollectedFinishQOwner {
                gate: &self.stop_gate,
                producers: &producers,
                discovery: &self.discovery_domain,
                detach: &self.producer_detach,
            },
            q,
            self.uprobe_scope,
            ticket,
            &mut self.links,
            &mut self.retained_static,
            &mut self.pid_pairs,
            &mut self.global_retirements,
            worker,
            |original| {
                take_collected_owned_link(ebpf, original)
                    .map(|owned| vec![counter_banks::retain_link(owned, keepalive.as_ref())])
            },
            || {
                events
                    .consumption_cut()
                    .map_err(|reason| anyhow!("collected EVENTS cut refused: {reason:?}"))
            },
            || Ok(events::discovery_drain_positions(discovery)),
            &self.deferred_group_slots,
            work,
        )
    }

    pub(crate) fn poll_collected_static_retirement(
        &mut self,
        q: &CollectedFinishQ,
        ticket: &CollectedRetirementTicket,
        work: usize,
    ) -> Result<RetirementProgress> {
        if work == 0 {
            return Ok(RetirementProgress::yielded());
        }
        let producers = self
            .drain_producers()
            .context("collected retirement has no original producers")?;
        let events = self
            .events_consumer
            .as_ref()
            .context("collected retirement needs retained EVENTS")?;
        let discovery = self
            .discovery_consumer
            .as_ref()
            .context("collected retirement needs retained DISCOVERY")?;
        let worker = self
            .cleanup_worker
            .as_ref()
            .context("collected retirement needs its prestarted worker")?;
        self.native_retirement.poll_collected_with(
            CollectedFinishQOwner {
                gate: &self.stop_gate,
                producers: &producers,
                discovery: &self.discovery_domain,
                detach: &self.producer_detach,
            },
            q,
            ticket,
            worker,
            || {
                events
                    .consumption_cut()
                    .map_err(|reason| anyhow!("collected EVENTS cut refused: {reason:?}"))
            },
            || Ok(events::discovery_drain_positions(discovery)),
            work,
        )
    }

    pub(crate) fn cancel_collected_static_retirement(
        &mut self,
        input: Option<&RetainedRetirementInput>,
        ticket: Option<&CollectedRetirementTicket>,
        work: usize,
    ) -> Result<RetirementProgress> {
        if work == 0 {
            return Ok(RetirementProgress::yielded());
        }
        let worker = self
            .cleanup_worker
            .as_ref()
            .context("collected cancellation needs its original worker")?;
        self.native_retirement
            .cancel_collected_with(input, ticket, worker, work)
    }

    /// Partition one collected removal into whole groups (which proceed
    /// natively) and partial shared-Multi members, recorded in
    /// `deferred_group_slots` for the terminal detach. Only a requested
    /// stop with proven quiescence may park removals this way.
    pub(crate) fn defer_collected_partial_groups(
        &mut self,
        q: &CollectedFinishQ,
        input: &mut Option<RetainedRetirementInput>,
        reserve: &crate::semantics_edge::resources::SemanticResourceReserver,
        work: usize,
    ) -> Result<DeferralProgress> {
        if work == 0 {
            return Ok(DeferralProgress::Yielded);
        }
        anyhow::ensure!(
            self.stop_gate.stop_requested() && self.stop_gate.quiescent(),
            native_retirement::DEFER_ENTRY_REFUSAL
        );
        self.native_retirement.defer_collected_with(
            q as *const CollectedFinishQ as usize,
            input,
            &self.links,
            &self.retained_static,
            &self.pid_pairs,
            &mut self.deferred_group_slots,
            reserve,
            work,
        )
    }

    /// Whether this Session retires collected removals physically at Q.
    /// Multi lanes close links natively; Singles lanes retire logically
    /// only and the terminal detach closes everything.
    pub(crate) fn collected_retirement_is_physical(&self) -> bool {
        Self::collected_retirement_is_physical_for(self.backend)
    }

    pub(crate) fn collected_retirement_is_physical_for(backend: AttachBackend) -> bool {
        backend == AttachBackend::Multi
    }

    /// Cleanup of an uncompleted new attachment is not coverage retirement.
    /// Healthy siblings actually detached by a partial Multi rebuild still
    /// retain their own physical retirement and reselection evidence.
    pub(crate) fn detach_failed_slots(&mut self, slots: &[Slot]) -> Result<DetachOutcome> {
        self.detach_slots_with_ended(slots, None, true)
    }

    pub(crate) fn detach_ended_pid_slots(
        &mut self,
        slots: &[Slot],
        owner: &crate::process::ProcessView,
        ended: &EndedPidRetirement,
    ) -> Result<DetachOutcome> {
        self.detach_slots_with_ended(slots, Some((owner, ended)), false)
    }

    fn detach_slots_with_ended(
        &mut self,
        slots: &[Slot],
        ended: Option<(&crate::process::ProcessView, &EndedPidRetirement)>,
        failed_cleanup: bool,
    ) -> Result<DetachOutcome> {
        anyhow::ensure!(
            !self.native_retirement.collected_blocking(),
            "selective detach refused while original native retirement owns the registry"
        );
        anyhow::ensure!(
            self.deferred_group_slots.is_empty(),
            "selective detach refused while a collected group deferral owns removals"
        );
        let requested: BTreeSet<_> = slots.iter().map(|slot| slot.index).collect();
        if let Some(banks) = &self.counter_banks {
            banks
                .validate_backend(self.backend)
                .map_err(|_| anyhow!("private counter retirement backend mismatch"))?;
            if self.backend == AttachBackend::Multi {
                // A Counts group's original cookies and published routes stay
                // immutable. Whole fresh groups can roll back, but an existing
                // group's surviving members must never be detached/rebuilt.
                validate_counter_group_retirement(&self.links, &requested)?;
            }
        }
        let excluded = if failed_cleanup {
            requested.clone()
        } else {
            BTreeSet::new()
        };
        let Some(affected) = plan_group_rebuild(&self.links, &requested) else {
            self.pid_pairs.invalidate(&requested);
            let detached = self.detach_links_with_ended(
                |link| match link {
                    // A group link drops only with all its members.
                    RegisteredLink::MultiUProbe { slots, .. } => {
                        !slots.is_empty() && slots.iter().all(|slot| requested.contains(slot))
                    }
                    _ => link.slots().iter().any(|slot| requested.contains(slot)),
                },
                ended.map(|(owner, proof)| (owner, proof, slots)),
                &excluded,
            );
            prune_linkless_retained(&mut self.retained_static, &self.links);
            return detached.map(|()| DetachOutcome::default());
        };
        self.rebuild_affected_groups(&requested, &affected, &excluded)
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
        excluded: &BTreeSet<u32>,
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
            self.embedded_flavor.unsafe_present,
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
        self.pid_pairs.invalidate(affected);
        let detached = self.detach_links_with_ended(
            |link| match link {
                RegisteredLink::MultiUProbe { slots, .. } => {
                    slots.iter().any(|slot| affected.contains(slot))
                }
                _ => link.slots().iter().any(|slot| requested.contains(slot)),
            },
            None,
            excluded,
        );
        self.global_retirements.select_retained(&survivors);
        detached?;
        prune_linkless_retained(&mut self.retained_static, &self.links);
        let continuity_baseline = match static_attachment_baseline_with(
            self,
            Session::pid_attach_baseline,
            Session::mutation_stopped,
        ) {
            Ok(baseline) => baseline,
            Err(error) => {
                let report = refused_group_rebuild(
                    affected.difference(requested).copied(),
                    rebuilt_groups,
                    &error.to_string(),
                );
                self.attach_failures
                    .extend(report.rebuild_failures.iter().cloned());
                return Ok(report);
            }
        };
        let pid = multi_link_pid(self.uprobe_scope);
        let (bundles, outcome) = reattach_rebuilt_groups_observed_with(
            &groups,
            |_| monotonic_ns(),
            |program, path, slice, is_return| {
                let prog_fd = prog_fds
                    .get(program)
                    .copied()
                    .expect("every rebuilt side pre-resolved its program fd");
                let (offsets, cookies): (Vec<u64>, Vec<u64>) = slice.iter().copied().unzip();
                pid_continuity::NativeAttempt::run(pid_continuity::comparable_monotonic_ns, || {
                    attach_group(prog_fd, pid, path, &offsets, &cookies, is_return)
                })
            },
            // Closing the owned fds detaches the rolled-back links.
            drop,
        );
        publish_kept_multi_bundles(
            &mut self.links,
            &mut self.retained_static,
            bundles,
            &survivors,
            &mut self.pid_pairs,
        );
        let AttachOutcome {
            successful,
            failures: mut rebuild_failures,
            completed: recompleted,
            continuity_rounds,
            exhausted: _,
        } = outcome;
        let current_sides = self.current_static_sides();
        self.pid_pairs.seal(
            &continuity_rounds,
            continuity_baseline,
            self.pid_lifecycle
                .as_ref()
                .and_then(|tap| tap.facts().ok())
                .map(|facts| facts.fault_serial),
            &self.links,
            &current_sides,
            &self.retained_static,
            pid_continuity::comparable_monotonic_ns,
        );
        self.global_retirements.seal(
            &continuity_rounds,
            &self.links,
            &current_sides,
            &self.retained_static,
            pid_continuity::comparable_monotonic_ns,
        );
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
            pending: None,
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

    /// Submit this Session's original producer ownership once, without
    /// waiting for native close. Maps, readers and targets remain in Session.
    /// Prior live submissions stay in the same worker and cumulative receipt.
    pub(crate) fn begin_owned_producer_detach(&mut self) -> Result<()> {
        anyhow::ensure!(
            !self.native_retirement.collected_blocking(),
            "terminal handoff waits for the original native retirement disposition"
        );
        match self.producer_detach {
            OwnedProducerDetach::Pending { .. } | OwnedProducerDetach::Complete => return Ok(()),
            OwnedProducerDetach::Unproved => bail!("producer detach ownership remains unproven"),
            OwnedProducerDetach::NotStarted => {}
        }
        // Mark terminal before any fallible transfer, so missing/partial
        // ownership never reopens attachment or mints an empty success later.
        self.producer_detach = OwnedProducerDetach::Unproved;
        if let Some(selected) = &self.native_selection {
            self.stop_gate.request_stop();
            self.image_coverage.fail();
            if let Err(error) = selected.close() {
                // Terminal failure cannot skip transfer of already owned links.
                self.detach_failures
                    .push(format!("closing selected native admission: {error:#}"));
            }
        }
        invalidate_pid_session(&mut self.pid_pairs, self.pid_lifecycle.as_ref());
        // No owner proof may survive retirement of the continuity hooks.
        self.image_coverage.fail();
        let started = std::time::Instant::now();
        let worker = self.take_cleanup_worker()?;
        let had_work = !self.links.is_empty()
            || self.instance.hook_link_count() != 0
            || worker.has_submissions();
        let leases = Arc::new(
            self.retained_static
                .values()
                .filter_map(RetainedStaticTarget::retirement_lease)
                .collect(),
        );
        worker.begin_terminal();
        let failures = submit_terminal_ownership(&worker, leases, |family| {
            self.take_terminal_ownership(family)
        });
        self.detach_failures.extend(failures);
        self.producer_detach = OwnedProducerDetach::Pending {
            worker,
            started,
            had_work,
            progress: cleanup_worker::DetachPollPrinter::new(),
        };
        Ok(())
    }

    fn take_terminal_ownership(
        &mut self,
        family: TerminalProducerFamily,
    ) -> Vec<Result<(OwnedLink, ProducerProgram)>> {
        let keepalive = self
            .counter_banks
            .as_ref()
            .map(|banks| Arc::clone(&banks.keepalive));
        match family {
            TerminalProducerFamily::Registered => {
                let mut outcomes = Vec::new();
                for link in std::mem::take(&mut self.links) {
                    let producer = link.producer();
                    let slots: Vec<u32> = link.slots().to_vec();
                    match take_owned_links(&mut self.ebpf, link) {
                        Ok(links) => {
                            // Only a take that yields owned handles submits
                            // the link: failed or empty takes prove nothing
                            // for the deferred mint gate.
                            if !links.is_empty() {
                                self.submitted_terminal_slots.extend(slots);
                            }
                            outcomes.extend(links.into_iter().map(|link| {
                                Ok((
                                    counter_banks::retain_link(link, keepalive.as_ref()),
                                    producer,
                                ))
                            }))
                        }
                        Err(error) => outcomes.push(Err(error)),
                    }
                }
                outcomes
            }
            TerminalProducerFamily::InstanceHooks => self
                .instance
                .take_owned_hooks(&mut self.ebpf)
                .into_iter()
                .map(|outcome| {
                    outcome.map(|(link, producer)| {
                        (
                            counter_banks::retain_link(link, keepalive.as_ref()),
                            producer,
                        )
                    })
                })
                .collect(),
        }
    }

    /// Drive only the original owned job. A second signal returns its typed
    /// interruption without a foreground close/join. Neither that result nor
    /// a failed transfer can later be promoted by observing empty links.
    pub(crate) fn finish_owned_producer_detach_driven(
        &mut self,
        second_signal: impl Fn() -> bool,
        out: &mut dyn std::io::Write,
    ) -> Result<()> {
        self.producer_detach.drive(
            &mut self.detach_failures,
            &mut self.producers_detached,
            &mut self.detach_wall_ms,
            second_signal,
            out,
        )
    }

    /// Non-consuming reap of the owned producer detach over this
    /// Session's exact detach fields. `Pending` keeps the SAME worker;
    /// only a joined receipt settles the Session.
    pub(crate) fn poll_owned_producer_detach(
        &mut self,
        out: &mut dyn std::io::Write,
    ) -> Result<ProducerDetachProgress> {
        self.producer_detach.poll(
            &mut self.detach_failures,
            &mut self.producers_detached,
            &mut self.detach_wall_ms,
            out,
        )
    }

    /// Existing one-step callers submit and then drive that exact job.
    pub(crate) fn detach_producers_driven(
        &mut self,
        second_signal: impl Fn() -> bool,
        out: &mut dyn std::io::Write,
    ) -> Result<()> {
        self.begin_owned_producer_detach()?;
        self.finish_owned_producer_detach_driven(second_signal, out)
    }

    /// Mint the native-owned terminal completion after the terminal
    /// sequence. Gates, in order: no prior destructive mint failure (a
    /// poisoned Session refuses before its poll, consuming nothing
    /// further), the producer detach worker joined (Complete, never an
    /// observed empty link set), the stop gate still proves Q, and every
    /// deferred group slot proven terminally submitted — all enforced
    /// fail-fast before the terminal poll, so a refused mint
    /// consumes nothing — then the selected gate (when present) reads
    /// back TERMINAL, one explicitly bounded terminal EVENTS poll runs,
    /// its known drain failures (backlog past the bound, reserved-but-
    /// uncommitted head) refuse before the scrub — so a failing scrub can
    /// neither run on doomed evidence nor preempt the by-name diagnostic
    /// — and the OBJECT_START scrub completes. The end adjudication
    /// re-checks the join gates with the post-poll Q read as defense in
    /// depth. Any post-poll failure poisons the mint: the poll ate a
    /// prefix a retry can never see again, so the refused Session can
    /// never mint afterwards. No partial completion exists.
    pub(crate) fn mint_native_completion(&mut self) -> Result<SessionNativeCompletion> {
        self.native_completion_mint.admit()?;
        let detach_complete = matches!(self.producer_detach, OwnedProducerDetach::Complete);
        let quiescent = self.stop_gate.quiescent();
        // Fail fast before the terminal poll consumes anything: a refused
        // mint must leave the backlog whole, or a retry could mint over
        // the split the refusal ate. (The selected gate below already
        // refuses fail-fast the same way.)
        SessionNativeCompletion::join_gates(detach_complete, quiescent)?;
        if !deferred_slots_proven(&self.deferred_group_slots, &self.submitted_terminal_slots) {
            bail!(
                "native completion unproved: deferred group slots were not all terminally submitted"
            );
        }
        let selected_terminal = match &self.native_selection {
            Some(selected) => {
                selected.require_terminal()?;
                true
            }
            None => false,
        };
        self.ensure_events_consumer()?;
        let verdict = {
            let consumer = self
                .events_consumer
                .as_mut()
                .context("retained EVENTS consumer vanished after creation")?;
            terminal_poll_verdict(consumer)
        };
        // Reject known drain failures BEFORE scrubbing: the verdict
        // already proves the mint cannot join. The refusal poisons the
        // mint — the poll consumed a prefix no retry can recover — and
        // the by-name diagnostic survives, never preempted by a scrub
        // that must not run on doomed evidence.
        SessionNativeCompletion::refuse_drain_verdict(verdict.backlog, verdict.head_pending)
            .inspect_err(|_| self.native_completion_mint.record_destructive_failure())?;
        let scrubbed_objects = object_stop::scrub_after_quiescence(&mut self.ebpf, &self.stop_gate)
            .inspect_err(|_| self.native_completion_mint.record_destructive_failure())
            .context("scrubbing object START for native completion")?;
        let completion = SessionNativeCompletion::from_joined_evidence(
            detach_complete,
            quiescent && self.stop_gate.quiescent(),
            verdict.backlog,
            verdict.head_pending,
            verdict.terminal_events,
            verdict.terminal_malformed,
            scrubbed_objects,
            self.detach_wall_ms,
            selected_terminal,
            self.events_domain.id(),
        );
        // The end adjudication re-checks the join gates with the post-poll
        // Q read: a refusal here still follows a consuming poll, so it
        // poisons the mint like any destructive failure.
        completion.inspect_err(|_| self.native_completion_mint.record_destructive_failure())
    }

    fn take_cleanup_worker(&mut self) -> Result<CleanupWorker> {
        self.cleanup_worker
            .take()
            .context("the prestarted cleanup worker has already been consumed")
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

    pub(crate) fn has_slot_link(&self, slot: u32) -> bool {
        links_cover_slot(&self.links, slot)
    }

    fn detach_links(&mut self, mut select: impl FnMut(&RegisteredLink) -> bool) -> Result<()> {
        self.detach_links_with_ended(&mut select, None, &BTreeSet::new())
    }

    fn detach_links_with_ended(
        &mut self,
        mut select: impl FnMut(&RegisteredLink) -> bool,
        ended: Option<(&crate::process::ProcessView, &EndedPidRetirement, &[Slot])>,
        excluded: &BTreeSet<u32>,
    ) -> Result<()> {
        anyhow::ensure!(
            !self.native_retirement.collected_blocking(),
            "native registry mutation refused during original retirement preparation"
        );
        anyhow::ensure!(
            self.deferred_group_slots.is_empty(),
            "native registry mutation refused while a collected group deferral owns removals"
        );
        // Resolve singles' fallible program lookup before extracting any
        // ownership. A refused lookup keeps all native handles untouched and
        // therefore opens no physical detach episode.
        let choices: Vec<_> = self.links.iter().map(&mut select).collect();
        for (link, chosen) in self.links.iter().zip(&choices) {
            if !chosen {
                continue;
            }
            if let RegisteredLink::UProbe { program, .. } = link {
                let _: &mut UProbe = self
                    .ebpf
                    .program_mut(program)
                    .with_context(|| format!("program {program} missing before static detach"))?
                    .try_into()?;
            }
        }
        let ended = ended
            .filter(|_| !self.mutation_stopped())
            .and_then(|(owner, proof, slots)| {
                proof.check(
                    &self.discovery_domain,
                    self.uprobe_scope,
                    owner,
                    slots,
                    &self.links,
                    &self.retained_static,
                )
            });
        // Program/group preflight has succeeded. Preserve the held physical
        // points immediately before these exact owned links enter retirement,
        // while the old complete entry/return pair can still be verified.
        let stopped = self.mutation_stopped();
        self.global_retirements.retire_selected(
            self.uprobe_scope,
            stopped,
            &self.links,
            &choices,
            excluded,
            &self.retained_static,
            pid_continuity::comparable_monotonic_ns,
        );
        let mut choices = choices.into_iter();
        let selected = extract_selected_links(&mut self.links, &mut self.pid_pairs, |_| {
            choices.next().expect("one choice per original link")
        });
        let affected: BTreeSet<_> = selected
            .iter()
            .filter(|link| {
                matches!(
                    link,
                    RegisteredLink::UProbe { .. } | RegisteredLink::MultiUProbe { .. }
                )
            })
            .flat_map(|link| link.slots().iter().copied())
            .collect();
        // All fallible group/program preparation has finished; these exact
        // owned handles are about to enter the first actual detach attempt.
        if matches!(self.uprobe_scope, UProbeScope::OneProcess(_)) {
            ended_pid_retirement::begin_detach_gap(
                &mut self.pid_pairs,
                &affected,
                pid_continuity::comparable_monotonic_ns(),
                &self.retained_static,
                ended,
            );
        }
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
        #[cfg(feature = "h6-reexec-diagnostic")]
        let diagnostic_span = self
            .reexec_diagnostic()
            .filter(|diag| diag.active())
            .map(|diag| {
                let phase = match &link {
                    RegisteredLink::UProbe {
                        program: "p11_return",
                        ..
                    } => DiagnosticPhase::NativeReturn,
                    RegisteredLink::UProbe { .. } => DiagnosticPhase::NativeEntry,
                    _ => DiagnosticPhase::NativeOther,
                };
                diag.begin(phase, [Some(0), None, None, None])
            });
        let result = detach_registered_link(&mut self.ebpf, link);
        #[cfg(feature = "h6-reexec-diagnostic")]
        if let Some(span) = diagnostic_span {
            span.finish_result(&result);
        }
        result
    }

    pub(crate) fn diagnostic() -> Result<Self> {
        Self::start_inner(
            &Scope::Pid(std::process::id()),
            CapturePolicy::Allowlisted,
            None,
            None,
            None,
            AttachBackend::Singles,
            None,
        )
    }

    pub(crate) fn attach_diagnostic_probe(&mut self, path: &Path, offset: u64) -> Result<()> {
        stopped_attachment_admission(self.mutation_stopped(), "diagnostic")?;
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

    /// The Session's retained drain producers: its native identity
    /// domain plus its retained EVENTS domain. The drain grant mints
    /// through this pair (never through two independently supplied
    /// halves), so the admission is always checked against the
    /// Session retaining the EVENTS identity it binds. `None` while
    /// the Session retains no native domain.
    #[allow(dead_code)] // No Session-loop wire until live activation; tests pair via test_pair.
    pub(crate) fn drain_producers(&self) -> Option<SessionDrainProducers> {
        Some(SessionDrainProducers {
            native: self.native_domain()?,
            events: self.events_domain(),
        })
    }

    /// The session's single retained `EVENTS` consumer, with exclusive
    /// `&mut` access: one cursor and one malformed total across every
    /// live, root-tail and terminal poll. Built once on first drain; the
    /// reader owns its mappings and never borrows this session's `Ebpf`.
    pub fn event_drain(&mut self) -> Result<&mut events::OwnedDrain> {
        self.event_drain_with_object_table().map(|(drain, _)| drain)
    }

    /// The session's single retained EVENTS consumer plus, on the
    /// attested allowlisted lane with verified object rows, the frozen
    /// receipt-bound decode table. One call hands out both disjoint
    /// borrows, so semantic collection retains object facts on exactly that
    /// lane. Ordinary drains validate their producer's full transport form and
    /// receive its base without semantic object authority.
    pub(crate) fn event_drain_with_object_table(
        &mut self,
    ) -> Result<(&mut events::OwnedDrain, Option<&ObjectRows>)> {
        self.ensure_events_consumer()?;
        let consumer = self
            .events_consumer
            .as_mut()
            .context("retained EVENTS consumer vanished after creation")?;
        let table = self.object_decode.as_ref().map(ObjectDecodeTable::rows);
        Ok((consumer, table))
    }

    /// Borrow the one retained cursor, its frozen decode rows and live fault
    /// maps together. These disjoint borrows add no drain or admission authority.
    /// The selected Joint caller must refuse a missing attested decode table.
    #[allow(dead_code)] // N1 collection bridge is staged until its real grants exist.
    pub(crate) fn joint_collection_io(
        &mut self,
    ) -> Result<(
        &mut events::OwnedDrain,
        Option<&ObjectRows>,
        InstanceMaps<'_>,
    )> {
        self.ensure_events_consumer()?;
        let consumer = self
            .events_consumer
            .as_mut()
            .context("retained EVENTS consumer vanished after creation")?;
        let table = self.object_decode.as_ref().map(ObjectDecodeTable::rows);
        Ok((consumer, table, InstanceMaps { ebpf: &self.ebpf }))
    }

    /// Observe only the SAME retained Session/Q domains and producer bounds.
    /// No consumer creation, polling, scrub or detach is performed here.
    pub(crate) fn collected_finish_discovery_domain(
        &self,
        q: &CollectedFinishQ,
    ) -> Result<&events::DiscoveryDomain> {
        anyhow::ensure!(
            self.matches_collected_finish_q(q),
            "foreign or no-longer-current Finish Q"
        );
        let events = self
            .events_consumer
            .as_ref()
            .context("Finish Q lost its original EVENTS cursor")?
            .consumption_cut()
            .map_err(|reason| anyhow!("Finish EVENTS cut refused: {reason:?}"))?;
        let discovery = events::discovery_drain_positions(
            self.discovery_consumer
                .as_ref()
                .context("Finish Q lost its original DISCOVERY cursor")?,
        );
        anyhow::ensure!(
            q.covers_events_bounds(&events)
                && events.producer_bound() == q.events_stop()
                && discovery.producer == q.discovery_stop()
                && discovery.consumer <= q.discovery_stop()
                && self.matches_collected_finish_q(q),
            "an original producer moved after Finish Q"
        );
        Ok(&self.discovery_domain)
    }

    pub(crate) fn joint_collection_io_at_q(
        &mut self,
        q: &CollectedFinishQ,
    ) -> Result<(
        &mut events::OwnedDrain,
        Option<&ObjectRows>,
        InstanceMaps<'_>,
    )> {
        self.collected_finish_discovery_domain(q)?;
        self.joint_collection_io()
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

    /// Staged DISCOVERY items currently held in the session FIFO.
    pub(crate) fn staged_discovery_len(&self) -> usize {
        self.discovery_staged.len()
    }

    /// The idle-wait descriptors against the shared discovery allowance:
    /// EVENTS always, and DISCOVERY while the staged FIFO plus what the
    /// Engine still holds leaves room. Stopping the poll while the Engine
    /// drains its backlog keeps the loop from spin-waking on a ring whose
    /// records cannot be staged yet.
    pub(crate) fn readiness_fds_with_held(&self, engine_held: usize) -> Vec<BorrowedFd<'_>> {
        let mut fds = vec![self.events_readiness_fd()];
        if DiscoveryStage::poll_discovery(self.discovery_staged.len(), engine_held) {
            fds.push(self.discovery_readiness_fd());
        }
        fds
    }

    /// Moves up to `quantum` DISCOVERY items off the kernel ring into the
    /// session's FIFO without applying any (RB-2), without letting staged
    /// plus `engine_held` exceed the shared 4,096-item allowance. The cap
    /// is enforced structurally by the FIFO; the outcome reports whether
    /// the allowance stopped the move.
    pub(crate) fn stage_discovery(
        &mut self,
        quantum: usize,
        engine_held: usize,
    ) -> Result<DiscoveryStageOutcome> {
        self.ensure_discovery_consumer()?;
        let consumer = self
            .discovery_consumer
            .as_mut()
            .context("retained DISCOVERY consumer vanished after creation")?;
        let shared_cap = DiscoveryStage::CAPACITY.saturating_sub(engine_held);
        Ok(self
            .discovery_staged
            .stage(quantum, shared_cap, || consumer.dequeue()))
    }

    /// Every staged item, in ring order, leaving the FIFO empty.
    pub(crate) fn take_staged_discovery(&mut self) -> Vec<events::DiscoveryItem> {
        self.discovery_staged.take()
    }

    pub(crate) fn discovery_dequeue(&mut self) -> Result<Option<events::DiscoveryItem>> {
        if let Some(item) = self.discovery_staged.pop() {
            return Ok(Some(item));
        }
        self.ensure_discovery_consumer()?;
        Ok(self
            .discovery_consumer
            .as_mut()
            .context("retained DISCOVERY consumer vanished after creation")?
            .dequeue())
    }

    fn ensure_events_consumer(&mut self) -> Result<()> {
        if self.events_consumer.is_none() {
            let transport = object_transport_rows_with(
                self.policy,
                self.object_decode.as_ref().map(|table| &table.rows),
                || freeze_object_decode_table(&self.ebpf).map(|table| table.rows),
            )?;
            let consumer = events::OwnedDrain::for_session_with_transport(
                &self.ebpf,
                &self.events_domain,
                transport,
            )?;
            self.events_consumer = Some(consumer);
            self.wire_trace_consumers()
                .map_err(|reason| anyhow!("private trace proof: {reason:?}"))?;
        }
        Ok(())
    }

    fn ensure_discovery_consumer(&mut self) -> Result<()> {
        let created = ensure_pid_discovery_consumer_with(
            &mut self.discovery_consumer,
            self.pid_lifecycle.as_ref(),
            || events::OwnedDiscoveryDrain::for_session(&self.ebpf, &self.discovery_domain),
        )?;
        if created {
            self.wire_trace_consumers()
                .map_err(|reason| anyhow!("private trace proof: {reason:?}"))
                .inspect_err(|_| {
                    if let Some(tap) = &self.pid_lifecycle {
                        tap.observe_failure();
                    }
                })?;
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
        anyhow::ensure!(
            !self.native_retirement.collected_blocking(),
            "quiescence cannot invalidate an active collected retirement registry"
        );
        anyhow::ensure!(
            self.deferred_group_slots.is_empty(),
            "quiescence cannot invalidate while a collected group deferral owns removals"
        );
        invalidate_pid_session(&mut self.pid_pairs, self.pid_lifecycle.as_ref());
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
        let state = crate::run::quiesce_with(
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
        );
        if matches!(state, crate::run::StopState::Quiesced { .. }) {
            object_stop::scrub_after_quiescence(&mut self.ebpf, gate)
                .context("scrubbing object START after terminal quiescence")?;
        }
        Ok(state)
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
        anyhow::ensure!(
            !self.native_retirement.collected_blocking(),
            "legacy discovery drain cannot invalidate an active collected retirement registry"
        );
        anyhow::ensure!(
            self.deferred_group_slots.is_empty(),
            "legacy discovery drain cannot invalidate while a collected group deferral owns removals"
        );
        invalidate_pid_session(&mut self.pid_pairs, self.pid_lifecycle.as_ref());
        self.ensure_discovery_consumer()?;
        let consumer = self
            .discovery_consumer
            .as_mut()
            .context("retained DISCOVERY consumer vanished after creation")?;
        collect_staged_discovery_to_position(&mut self.discovery_staged, consumer, stop, quantum)
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

    /// Retained current attachment and exact descriptor readback, obtained
    /// by the Session itself. No caller-supplied positive attachment facts.
    pub(crate) fn semantic_receipt_target(
        &self,
        slot: u32,
    ) -> std::result::Result<
        crate::discovery::identity::RetainedInventoryTarget,
        crate::semantic_capture::CurrentReceiptRefusal,
    > {
        use crate::semantic_capture::CurrentReceiptRefusal as Refusal;
        semantic_receipt_readback(self.policy, self.semantic_descriptors())?;
        let sides = self.current_static_sides();
        if !sides.contains(&(slot, ProbeSide::Entry)) || !sides.contains(&(slot, ProbeSide::Return))
        {
            return Err(Refusal::Attachment);
        }
        let retained = self.retained_static.get(&slot).ok_or(Refusal::Attachment)?;
        if retained.slot.index != slot {
            return Err(Refusal::Attachment);
        }
        let watched = self
            .instance
            .watched(retained.slot.object)
            .ok_or(Refusal::Attachment)?;
        let target = watched.retained_target();
        if target.check_unchanged() != Ok(true) {
            return Err(Refusal::Attachment);
        }
        Ok(target)
    }

    /// Read current identity and complete epochs under the original custody;
    /// these are I/O results, not a constructor for registration authority.
    pub(crate) fn semantic_receipt_state(
        &mut self,
        pin: &crate::process::PidPin,
        image: p11scope_ebpf_common::ImageIdentity,
        endpoint: crate::semantic_capture::Endpoint,
        slot: u32,
        deadline: std::time::Instant,
    ) -> std::result::Result<
        (
            p11scope_ebpf_common::ImageIdentity,
            image_query::CompleteEpochs,
            crate::discovery::identity::RetainedInventoryTarget,
        ),
        crate::semantic_capture::CurrentReceiptRefusal,
    > {
        use crate::semantic_capture::CurrentReceiptRefusal as Refusal;
        let budget = || {
            if std::time::Instant::now() < deadline {
                Ok(())
            } else {
                Err(Refusal::Deadline)
            }
        };
        budget()?;
        if self.instance_endpoint(slot) != Some(endpoint) {
            return Err(Refusal::Attachment);
        }
        let target = self.semantic_receipt_target(slot)?;
        let window = capture::ReadWindow::new(16_384, deadline).map_err(|_| Refusal::Deadline)?;
        let before = self
            .query_images(&[pin], window)
            .map_err(semantic_receipt_query_refusal)?;
        let before_image = before.image(image.task_cookie).ok_or(Refusal::Epoch)?;
        budget()?;
        let first = self
            .instance_maps()
            .complete_epochs(
                pin.pidfd().map_err(|_| Refusal::Custody)?,
                endpoint.file_slot,
            )
            .map_err(|_| Refusal::Audit)?;
        budget()?;
        let second = self
            .instance_maps()
            .complete_epochs(
                pin.pidfd().map_err(|_| Refusal::Custody)?,
                endpoint.file_slot,
            )
            .map_err(|_| Refusal::Audit)?;
        let after = self
            .query_images(&[pin], window)
            .map_err(semantic_receipt_query_refusal)?;
        let after_image = after.image(image.task_cookie).ok_or(Refusal::Epoch)?;
        budget()?;
        let current_target = self.semantic_receipt_target(slot)?;
        if self.instance_endpoint(slot) != Some(endpoint)
            || !Arc::ptr_eq(
                &target.retirement_lease(),
                &current_target.retirement_lease(),
            )
            || target.check_unchanged() != Ok(true)
        {
            return Err(Refusal::Attachment);
        }
        if first != second || before_image != after_image {
            return Err(Refusal::Epoch);
        }
        Ok((after_image, second, current_target))
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

    /// Object-attribute capture availability in the embedded bytes this
    /// session was set up with. Stubbed (P0) bytes disclaim attribute
    /// coverage; FULL bytes report available. Setup already refused on
    /// mismatch or undeterminable bytes, so this never falls back.
    pub(crate) fn object_capture_evidence(&self) -> crate::render::ObjectCaptureEvidence {
        // The bytes rule: report the embedded object's capture, not the
        // build feature, from the flavor checked at setup.
        crate::render::ObjectCaptureEvidence::for_build(self.embedded_flavor.stubbed)
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

/// One static original transfers as one owning payload. Keep the native
/// legacy perf representation intact instead of flattening per-CPU leaves.
fn take_collected_owned_link(ebpf: &mut Ebpf, original: RegisteredLink) -> Result<OwnedLink> {
    match original {
        RegisteredLink::MultiUProbe { fds, .. } => Ok(OwnedLink::Multi(fds)),
        RegisteredLink::UProbe { program, id, .. } => {
            let probe: &mut UProbe = ebpf
                .program_mut(program)
                .with_context(|| format!("program {program} missing during collected transfer"))?
                .try_into()?;
            Ok(OwnedLink::Probe(probe.take_link(id).with_context(
                || format!("transferring original {program}"),
            )?))
        }
        _ => bail!("collected retirement cannot transfer a nonstatic registration"),
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
                Err(link) => Ok(vec![OwnedLink::Probe(link)]),
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
                Err(link) => Ok(vec![OwnedLink::Probe(link)]),
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
        if self.counter_banks.is_some() {
            self.stop_gate.request_stop();
        }
        if let Some(selected) = &self.native_selection {
            self.stop_gate.request_stop();
            let _ = selected.close();
        }
        invalidate_pid_session(&mut self.pid_pairs, self.pid_lifecycle.as_ref());
        // Refuse continuity before closing any owned producer/hook link.
        self.image_coverage.fail();
        let keepalive = self
            .counter_banks
            .as_ref()
            .map(|banks| Arc::clone(&banks.keepalive));
        let ebpf = &mut self.ebpf;
        self.native_retirement.abandon_collected_with(
            &self.links,
            self.cleanup_worker.as_ref(),
            |original| {
                take_collected_owned_link(ebpf, original)
                    .map(|owned| vec![counter_banks::retain_link(owned, keepalive.as_ref())])
            },
        );
        // Never block on a worker-owned link: leftovers move to the
        // worker and close in the background (at process exit the kernel
        // finishes). Evidence is best-effort; there is no caller to fail.
        if self.links.is_empty() {
            return;
        }
        let leases = Arc::new(
            self.retained_static
                .values()
                .filter_map(RetainedStaticTarget::retirement_lease)
                .collect(),
        );
        let mut owned = Vec::new();
        let keepalive = self
            .counter_banks
            .as_ref()
            .map(|banks| Arc::clone(&banks.keepalive));
        for link in std::mem::take(&mut self.links) {
            let producer = link.producer();
            if let Ok(links) = take_owned_links(&mut self.ebpf, link) {
                owned.extend(links.into_iter().map(|link| {
                    (
                        counter_banks::retain_link(link, keepalive.as_ref()),
                        producer,
                    )
                }));
            }
        }
        if let Some(worker) = self.cleanup_worker.take() {
            worker.submit(owned, leases, DetachOrder);
            drop(worker);
        } else if !owned.is_empty() {
            // A terminal/second-signal path already owns the sole worker.
            // Never introduce another thread or block this destructor on
            // native closes; process exit releases this explicit abandon.
            std::mem::forget((owned, leases));
        }
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
pub(crate) use tests::CollectedFinishQObserverForTest;

#[cfg(test)]
mod tests {
    use super::publish_and_freeze_object_descriptors_with;
    use crate::attach::capture::NativeDomainId;
    use crate::inventory_semantics::SemanticRefusal;
    use p11scope_ebpf_common::object_wire::{
        OBJECT_ACTION_ACCESS, OBJECT_ACTION_COPY, ObjectDescriptorWire, none_object_wire,
        publish_object_descriptors,
    };
    use std::collections::BTreeMap;

    /// A real STOP_GATE mapping, with a second mapping standing in only for
    /// native atomic updates. No Q receipt is constructed by the fixture.
    struct FinishQGate {
        gate: super::StopGate,
        writer: std::ptr::NonNull<std::sync::atomic::AtomicU64>,
        len: usize,
        _file: std::fs::File,
    }

    impl FinishQGate {
        fn new() -> Self {
            use std::os::fd::{AsFd, AsRawFd};

            let file = tempfile::tempfile().unwrap();
            let len = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
            file.set_len(u64::try_from(len).unwrap()).unwrap();
            let gate = super::StopGate::from_map_fd(file.as_fd()).unwrap();
            let mapping = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED,
                    file.as_raw_fd(),
                    0,
                )
            };
            assert_ne!(mapping, libc::MAP_FAILED);
            Self {
                gate,
                writer: std::ptr::NonNull::new(mapping.cast()).unwrap(),
                len,
                _file: file,
            }
        }

        fn native_word(&self, value: u64) {
            // Both mappings refer to the same aligned AtomicU64 cell.
            unsafe { self.writer.as_ref() }.store(value, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl Drop for FinishQGate {
        fn drop(&mut self) {
            unsafe { libc::munmap(self.writer.as_ptr().cast(), self.len) };
        }
    }

    /// Reuse the Session's actual observer with the fanout scene's ORIGINAL
    /// EVENTS drain. This owner retains its DISCOVERY drain and real mmap
    /// STOP_GATE for the whole fixture; neither ring positions nor Q can be
    /// supplied by a caller. It never polls, scrubs, or creates another EVENTS
    /// cursor, and an observed Q leaves the DISCOVERY record undelivered.
    pub(crate) struct CollectedFinishQObserverForTest {
        gate: FinishQGate,
        producers: super::SessionDrainProducers,
        discovery_domain: crate::events::DiscoveryDomain,
        discovery: crate::events::DiscoveryDrain<crate::events::ScriptedRecords>,
        detach: super::OwnedProducerDetach,
    }

    impl CollectedFinishQObserverForTest {
        pub(crate) fn new(producers: &super::SessionDrainProducers) -> Self {
            Self::with_discovery_bytes(producers, [vec![0]])
        }

        /// Choose the original fixture records before the retained drain is
        /// created. This does not change Q observation or accept positions.
        pub(crate) fn with_discovery_bytes(
            producers: &super::SessionDrainProducers,
            records: impl IntoIterator<Item = Vec<u8>>,
        ) -> Self {
            let records: Vec<_> = records.into_iter().collect();
            let bound = records.len();
            let discovery_domain = crate::events::DiscoveryDomain::test_standin(0xf1d5);
            Self {
                gate: FinishQGate::new(),
                producers: producers.clone(),
                discovery: crate::events::DiscoveryDrain::over_domain(
                    crate::events::ScriptedRecords::records(records, bound),
                    discovery_domain.clone(),
                ),
                discovery_domain,
                detach: super::OwnedProducerDetach::NotStarted,
            }
        }

        pub(crate) fn request_stop(&self) {
            self.gate.gate.request_stop();
        }

        /// The collected-deferral entry condition over the live gate word.
        pub(crate) fn collected_defer_entry_open(&self) -> bool {
            self.gate.gate.stop_requested() && self.gate.gate.quiescent()
        }

        /// Set the gate word directly. Production STOP never clears and
        /// never admits a body after quiescence; the states this reaches
        /// exist only to prove the deferral entry reads live state.
        pub(crate) fn set_gate_word_for_test(&self, word: u64) {
            self.gate.native_word(word);
        }

        pub(crate) fn discovery_domain(&self) -> &crate::events::DiscoveryDomain {
            &self.discovery_domain
        }

        pub(crate) fn discovery_remaining(&self) -> usize {
            self.discovery.source().remaining()
        }

        pub(crate) fn discovery_drain(
            &self,
        ) -> &crate::events::DiscoveryDrain<crate::events::ScriptedRecords> {
            &self.discovery
        }

        pub(super) fn retained_owner(&self) -> super::CollectedFinishQOwner<'_> {
            super::CollectedFinishQOwner {
                gate: &self.gate.gate,
                producers: &self.producers,
                discovery: &self.discovery_domain,
                detach: &self.detach,
            }
        }

        /// Borrow the SAME original drain used by the private Q observer.
        pub(crate) fn discovery_drain_mut(
            &mut self,
        ) -> &mut crate::events::DiscoveryDrain<crate::events::ScriptedRecords> {
            &mut self.discovery
        }

        pub(crate) fn observe(
            &self,
            expected: &super::SessionDrainProducers,
            grant: Option<&crate::semantics_objects::journal::SessionDrainGrant>,
            events: &crate::events::EventDrain<crate::events::ScriptedRecords>,
        ) -> anyhow::Result<Option<super::CollectedFinishQ>> {
            super::observe_collected_finish_q_with(
                super::CollectedFinishQOwner {
                    gate: &self.gate.gate,
                    producers: &self.producers,
                    discovery: &self.discovery_domain,
                    detach: &self.detach,
                },
                expected,
                grant,
                || {
                    events.consumption_cut().map_err(|reason| {
                        anyhow::anyhow!("original EVENTS cut refused: {reason:?}")
                    })
                },
                || Ok(crate::events::discovery_drain_positions(&self.discovery)),
            )
        }
    }

    #[derive(Clone, Copy)]
    enum FinishQReadControl {
        Normal,
        EventsError,
        DiscoveryError,
        LoseQuiescence,
    }

    struct FinishQFixture {
        gate: FinishQGate,
        producers: super::SessionDrainProducers,
        discovery_domain: crate::events::DiscoveryDomain,
        detach: super::OwnedProducerDetach,
        events: crate::events::EventDrain<crate::events::ScriptedRecords>,
        discovery: crate::events::DiscoveryDrain<crate::events::ScriptedRecords>,
        reads: std::cell::Cell<(usize, usize)>,
    }

    impl FinishQFixture {
        fn new(native: NativeDomainId) -> Self {
            use crate::events::{
                DiscoveryDomain, DiscoveryDrain, EventDrain, EventsDomain, ScriptedRecords,
            };

            let events = EventsDomain::test_standin(0xf1a1);
            let discovery_domain = DiscoveryDomain::test_standin(0xf1d1);
            Self {
                gate: FinishQGate::new(),
                producers: super::SessionDrainProducers::test_pair(native, events.clone()),
                discovery_domain: discovery_domain.clone(),
                detach: super::OwnedProducerDetach::NotStarted,
                events: EventDrain::over_domain(
                    ScriptedRecords::records([vec![0], vec![0]], 4),
                    events,
                ),
                discovery: DiscoveryDrain::over_domain(
                    ScriptedRecords::records([vec![0]], 1),
                    discovery_domain,
                ),
                reads: std::cell::Cell::new((0, 0)),
            }
        }

        fn observe(
            &self,
            expected: &super::SessionDrainProducers,
            grant: Option<&crate::semantics_objects::journal::SessionDrainGrant>,
            control: FinishQReadControl,
        ) -> anyhow::Result<Option<super::CollectedFinishQ>> {
            let owner = super::CollectedFinishQOwner {
                gate: &self.gate.gate,
                producers: &self.producers,
                discovery: &self.discovery_domain,
                detach: &self.detach,
            };
            // This is the SAME private observer builder that Session must
            // supply with its own fields. Only native ring reads are leaves.
            super::observe_collected_finish_q_with(
                owner,
                expected,
                grant,
                || {
                    let (events, discovery) = self.reads.get();
                    self.reads.set((events + 1, discovery));
                    if matches!(control, FinishQReadControl::EventsError) {
                        anyhow::bail!("injected EVENTS position failure");
                    }
                    self.events
                        .consumption_cut()
                        .map_err(|reason| anyhow::anyhow!("EVENTS cut refused: {reason:?}"))
                },
                || {
                    let (events, discovery) = self.reads.get();
                    self.reads.set((events, discovery + 1));
                    if matches!(control, FinishQReadControl::DiscoveryError) {
                        anyhow::bail!("injected DISCOVERY position failure");
                    }
                    if matches!(control, FinishQReadControl::LoseQuiescence) {
                        self.gate
                            .native_word(p11scope_ebpf_common::STOP_GATE_STOP | 1);
                    }
                    Ok(crate::events::discovery_drain_positions(&self.discovery))
                },
            )
        }
    }

    /// Removing either STOP or the count-zero condition would mint authority
    /// before the actual native producer gate has reached Q.
    #[test]
    fn collected_finish_q_requires_actual_stopped_quiescence() {
        let _session_port: fn(
            &mut super::Session,
            &super::SessionDrainProducers,
            Option<&crate::semantics_objects::journal::SessionDrainGrant>,
        ) -> anyhow::Result<Option<super::CollectedFinishQ>> =
            super::Session::observe_collected_finish_q;
        let fixture = FinishQFixture::new(NativeDomainId::mint());
        for word in [0, 3, p11scope_ebpf_common::STOP_GATE_STOP | 3] {
            fixture.gate.native_word(word);
            assert!(
                fixture
                    .observe(&fixture.producers, None, FinishQReadControl::Normal)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(fixture.reads.get(), (0, 0));
        }
        fixture.gate.native_word(0);
        fixture.gate.gate.request_stop();
        let q = fixture
            .observe(&fixture.producers, None, FinishQReadControl::Normal)
            .unwrap()
            .unwrap();
        assert!(q.matches_owner(&fixture.producers, &fixture.discovery_domain));
        assert_eq!((q.events_stop(), q.discovery_stop()), (16, 8));
        assert_eq!(fixture.events.source().remaining(), 2);
        assert_eq!(fixture.discovery.source().remaining(), 1);
    }

    /// Numeric map IDs alone cannot splice another retained allocation;
    /// optional drain metadata must neither be ignored nor upgraded from None.
    #[test]
    fn collected_finish_q_binds_producers_grant_and_detach_owner() {
        use crate::events::{DiscoveryDomain, EventsDomain};
        use crate::semantics_objects::journal::{SessionDrainGrant, tests::AttestationFixture};

        let mut admission = AttestationFixture::new(p11scope_ebpf_common::ImageIdentity {
            task_cookie: 71,
            exec_id: 0,
        });
        let mut fixture = FinishQFixture::new(admission.domain());
        fixture.gate.gate.request_stop();
        let input = admission.admit_function("C_CreateObject");
        let grant = SessionDrainGrant::observe(&fixture.producers, &input).unwrap();
        let foreign_events = super::SessionDrainProducers::test_pair(
            admission.domain(),
            EventsDomain::test_standin(0xf1a2),
        );
        let foreign_grant = SessionDrainGrant::observe(&foreign_events, &input).unwrap();
        let equal_id_allocation = super::SessionDrainProducers::test_pair(
            admission.domain(),
            EventsDomain::test_standin(0xf1a1),
        );
        let foreign_native = super::SessionDrainProducers::test_pair(
            NativeDomainId::mint(),
            fixture.producers.events.clone(),
        );
        assert!(grant.matches_producers(&fixture.producers));
        assert!(!grant.matches_producers(&foreign_events));
        assert!(!grant.matches_producers(&foreign_native));
        for expected in [&foreign_events, &equal_id_allocation, &foreign_native] {
            assert!(
                fixture
                    .observe(expected, Some(&grant), FinishQReadControl::Normal)
                    .is_err()
            );
        }
        assert!(
            fixture
                .observe(
                    &fixture.producers,
                    Some(&foreign_grant),
                    FinishQReadControl::Normal
                )
                .is_err()
        );
        assert_eq!(fixture.reads.get(), (0, 0));
        let q = fixture
            .observe(&fixture.producers, Some(&grant), FinishQReadControl::Normal)
            .unwrap()
            .unwrap();
        assert!(q.matches_retained_grant(&grant));
        assert!(!q.matches_owner(&equal_id_allocation, &fixture.discovery_domain));
        assert!(!q.matches_owner(&fixture.producers, &DiscoveryDomain::test_standin(0xf1d1)));
        let negative_only = fixture
            .observe(&fixture.producers, None, FinishQReadControl::Normal)
            .unwrap()
            .unwrap();
        assert!(!negative_only.matches_retained_grant(&grant));
        for detach in [
            super::OwnedProducerDetach::Unproved,
            super::OwnedProducerDetach::Complete,
            super::OwnedProducerDetach::Pending {
                worker: super::CleanupWorker::pre_start_with_spawn(
                    Box::new(|_, _| Ok(())),
                    std::sync::Arc::new(|| std::time::Duration::ZERO),
                    |_| Err(std::io::Error::other("fixture starts no cleanup thread")),
                ),
                started: std::time::Instant::now(),
                had_work: false,
                progress: cleanup_worker::DetachPollPrinter::new(),
            },
        ] {
            fixture.detach = detach;
            let before = fixture.reads.get();
            assert!(
                fixture
                    .observe(&fixture.producers, Some(&grant), FinishQReadControl::Normal)
                    .is_err()
            );
            assert_eq!(fixture.reads.get(), before);
        }
    }

    /// A single early gate read or swallowed position error must not mint Q.
    #[test]
    fn collected_finish_q_rechecks_quiescence_and_preserves_read_errors() {
        for control in [
            FinishQReadControl::EventsError,
            FinishQReadControl::DiscoveryError,
            FinishQReadControl::LoseQuiescence,
        ] {
            let fixture = FinishQFixture::new(NativeDomainId::mint());
            fixture.gate.gate.request_stop();
            let result = fixture.observe(&fixture.producers, None, control);
            if matches!(control, FinishQReadControl::LoseQuiescence) {
                assert!(result.unwrap().is_none());
                assert_eq!(fixture.reads.get(), (1, 1));
            } else {
                assert!(result.is_err());
            }
            assert_eq!(fixture.events.source().remaining(), 2);
            assert_eq!(fixture.discovery.source().remaining(), 1);
        }
    }

    /// Q is an upper bound, not an assertion that this original drained or
    /// was clean. Another cursor and a post-Q write cannot fit that bound.
    #[test]
    fn collected_finish_q_bounds_original_cut_without_claiming_drain() {
        use crate::events::{EventDrain, ScriptedRecords};
        use std::ops::ControlFlow;

        let mut fixture = FinishQFixture::new(NativeDomainId::mint());
        let original = fixture.events.consumption_cut().unwrap();
        assert!(!original.is_drained());
        fixture.events.source_mut().push_record(vec![0]);
        fixture.gate.gate.request_stop();
        let q = fixture
            .observe(&fixture.producers, None, FinishQReadControl::Normal)
            .unwrap()
            .unwrap();
        assert_eq!(q.events_stop(), 24);
        assert!(q.covers_events_bounds(&original));
        assert!(!q.events_at_bound(&original));
        let other_cursor = EventDrain::over_domain(
            ScriptedRecords::records([], 0),
            fixture.producers.events.clone(),
        );
        assert!(!q.covers_events_bounds(&other_cursor.consumption_cut().unwrap()));
        fixture.events.poll(Some(1), |_| ControlFlow::Continue(()));
        let prefix = fixture.events.consumption_cut().unwrap();
        assert!(q.covers_events_bounds(&prefix));
        assert!(!q.events_at_bound(&prefix));
        assert_eq!(
            fixture.events.malformed(),
            1,
            "bounds do not erase observed loss"
        );
        fixture.events.poll(Some(2), |_| ControlFlow::Continue(()));
        let end = fixture.events.consumption_cut().unwrap();
        assert!(q.covers_events_bounds(&end));
        assert!(q.events_at_bound(&end));
        fixture.events.source_mut().push_record(vec![0]);
        assert!(!q.covers_events_bounds(&fixture.events.consumption_cut().unwrap()));
    }

    #[test]
    fn object_transport_ordinary_policy_requires_verified_rows() {
        use super::{CapturePolicy, object_transport_rows_with};
        use std::sync::Arc;

        for command in ["profile", "trace"] {
            let policy = CapturePolicy::from_cli(command, false, false).unwrap();
            let rows = Arc::new(publish_object_descriptors());
            let mut reads = 0;
            let selected = object_transport_rows_with(policy, None, || {
                reads += 1;
                Ok(Arc::clone(&rows))
            })
            .unwrap()
            .unwrap();
            assert_eq!(reads, 1);
            assert!(Arc::ptr_eq(&selected, &rows));
            let refused = object_transport_rows_with(policy, None, || {
                anyhow::bail!("injected frozen-map readback failure")
            });
            assert!(
                refused.is_err(),
                "{command} must not silently fall back to 368-byte records"
            );
        }
    }

    #[test]
    fn object_transport_attested_rows_are_shared_without_new_authority() {
        use super::{CapturePolicy, object_transport_rows_with};
        use std::sync::Arc;

        let rows = Arc::new(publish_object_descriptors());
        let selected = object_transport_rows_with(CapturePolicy::Allowlisted, Some(&rows), || {
            panic!("attested transport reuses its verified rows")
        })
        .unwrap()
        .unwrap();
        assert!(Arc::ptr_eq(&selected, &rows));
        for policy in [
            CapturePolicy::AggregateOnly,
            CapturePolicy::UnsafeUnvalidatedMetadata,
        ] {
            assert!(
                object_transport_rows_with(policy, Some(&rows), || {
                    panic!("non-object policy must not acquire transport rows")
                })
                .unwrap()
                .is_none()
            );
        }
    }

    struct FakeObjectMap {
        rows: BTreeMap<u32, ObjectDescriptorWire>,
        order: Vec<u32>,
        frozen: bool,
        frozen_at_readback: Vec<bool>,
        fail_set: Option<u32>,
        fail_readbacks: usize,
        fail_freeze: bool,
    }

    impl FakeObjectMap {
        fn new() -> Self {
            Self {
                rows: BTreeMap::new(),
                order: Vec::new(),
                frozen: false,
                frozen_at_readback: Vec::new(),
                fail_set: None,
                fail_readbacks: 0,
                fail_freeze: false,
            }
        }

        fn set(map: &mut Self, index: u32, row: ObjectDescriptorWire) -> anyhow::Result<()> {
            if map.frozen {
                anyhow::bail!("frozen map rejects writes");
            }
            if Some(index) == map.fail_set {
                anyhow::bail!("injected set failure");
            }
            map.order.push(index);
            map.rows.insert(index, row);
            Ok(())
        }

        fn readback(map: &mut Self) -> anyhow::Result<Vec<ObjectDescriptorWire>> {
            if map.fail_readbacks > 0 {
                map.fail_readbacks -= 1;
                anyhow::bail!("injected readback failure");
            }
            map.frozen_at_readback.push(map.frozen);
            (0..105)
                .map(|index| {
                    map.rows
                        .get(&index)
                        .copied()
                        .ok_or_else(|| anyhow::anyhow!("missing row {index}"))
                })
                .collect()
        }

        fn freeze(map: &mut Self) -> anyhow::Result<()> {
            if map.fail_freeze {
                anyhow::bail!("injected freeze failure");
            }
            map.frozen = true;
            Ok(())
        }
    }

    #[test]
    fn object_producer_publication_reads_freezes_and_rechecks_same_state() {
        let domain = NativeDomainId::mint();
        let proof = publish_and_freeze_object_descriptors_with(
            FakeObjectMap::new(),
            domain,
            FakeObjectMap::set,
            FakeObjectMap::readback,
            FakeObjectMap::freeze,
        )
        .unwrap();
        assert_eq!(proof.rows, publish_object_descriptors());
        assert_eq!(proof.domain, domain);
        assert_eq!(proof.state.order, (0..105).collect::<Vec<_>>());
        assert_eq!(proof.state.frozen_at_readback, vec![false, true]);
        assert!(proof.state.frozen);
    }

    #[test]
    fn object_custody_publication_encodes_canonical_rows() {
        use super::object_descriptor_row_bytes;
        use p11scope_ebpf_common::object_wire::{
            OBJECT_ACTION_DESTROY, OBJECT_GUARD_NAMED, verify_object_descriptors,
        };
        let rows = publish_object_descriptors();
        assert!(verify_object_descriptors(&rows));
        assert_eq!(rows.len(), 105);
        for (index, row) in rows.iter().enumerate() {
            let bytes = object_descriptor_row_bytes(row);
            assert_eq!(
                u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
                row.function,
                "row {index} function"
            );
            assert_eq!(&bytes[4..6], &row.input_args, "row {index} inputs");
            assert_eq!(&bytes[6..8], &row.result_args, "row {index} results");
            assert_eq!(&bytes[8..12], &row.template_args, "row {index} template");
            assert_eq!(bytes[12], row.find_capacity_arg, "row {index} capacity");
            assert_eq!(bytes[13], row.find_count_arg, "row {index} count");
            assert_eq!(bytes[14], row.action, "row {index} action");
            assert_eq!(bytes[15], row.guard, "row {index} guard");
        }
        assert_eq!(rows[0], none_object_wire());
        assert_eq!(object_descriptor_row_bytes(&rows[0])[14..], [0, 0]);
        assert_eq!(rows[23].function, 22);
        assert_eq!(rows[23].action, OBJECT_ACTION_DESTROY);
        assert_eq!(rows[23].guard, OBJECT_GUARD_NAMED);
    }

    #[test]
    fn object_producer_publication_stops_at_each_io_failure() {
        for fail_at in [0, 57, 104] {
            let mut map = FakeObjectMap::new();
            map.fail_set = Some(fail_at);
            let result = publish_and_freeze_object_descriptors_with(
                map,
                NativeDomainId::mint(),
                FakeObjectMap::set,
                FakeObjectMap::readback,
                FakeObjectMap::freeze,
            );
            assert!(
                matches!(result, Err(SemanticRefusal::Descriptor)),
                "set failure at {fail_at} refuses"
            );
        }
        let mut map = FakeObjectMap::new();
        map.fail_readbacks = 1;
        let result = publish_and_freeze_object_descriptors_with(
            map,
            NativeDomainId::mint(),
            FakeObjectMap::set,
            FakeObjectMap::readback,
            FakeObjectMap::freeze,
        );
        assert!(matches!(result, Err(SemanticRefusal::Descriptor)));
        let mut calls = 0;
        let result = publish_and_freeze_object_descriptors_with(
            FakeObjectMap::new(),
            NativeDomainId::mint(),
            FakeObjectMap::set,
            |map: &mut FakeObjectMap| {
                calls += 1;
                if calls == 2 {
                    return Err(anyhow::anyhow!("second readback fails"));
                }
                FakeObjectMap::readback(map)
            },
            FakeObjectMap::freeze,
        );
        assert!(matches!(result, Err(SemanticRefusal::Descriptor)));
        let mut map = FakeObjectMap::new();
        map.fail_freeze = true;
        let result = publish_and_freeze_object_descriptors_with(
            map,
            NativeDomainId::mint(),
            FakeObjectMap::set,
            FakeObjectMap::readback,
            FakeObjectMap::freeze,
        );
        assert!(matches!(result, Err(SemanticRefusal::Descriptor)));
    }

    #[test]
    fn object_producer_publication_refuses_every_inexact_table() {
        fn published() -> FakeObjectMap {
            let mut map = FakeObjectMap::new();
            for (index, row) in publish_object_descriptors().iter().copied().enumerate() {
                FakeObjectMap::set(&mut map, index as u32, row).unwrap();
            }
            map
        }
        let canonical = publish_object_descriptors().to_vec();
        let mut swapped = canonical.clone();
        swapped.swap(21, 22);
        let mut altered_eligible = canonical.clone();
        altered_eligible[21].action = OBJECT_ACTION_COPY;
        let mut altered_none = canonical.clone();
        altered_none[5].action = OBJECT_ACTION_ACCESS;
        let short = canonical[..104].to_vec();
        let mut long = canonical.clone();
        long.push(none_object_wire());
        let cases: Vec<(&str, Vec<ObjectDescriptorWire>)> = vec![
            ("swapped", swapped),
            ("altered eligible", altered_eligible),
            ("altered NONE", altered_none),
            ("short", short),
            ("long", long),
            ("blank", vec![none_object_wire(); 105]),
            ("empty", Vec::new()),
        ];
        for (label, table) in cases {
            let result = publish_and_freeze_object_descriptors_with(
                published(),
                NativeDomainId::mint(),
                FakeObjectMap::set,
                |_: &mut FakeObjectMap| Ok(table.clone()),
                FakeObjectMap::freeze,
            );
            assert!(
                matches!(result, Err(SemanticRefusal::Descriptor)),
                "{label} readback refuses"
            );
        }
        // A corrupting write path refuses against an honest readback.
        let result = publish_and_freeze_object_descriptors_with(
            FakeObjectMap::new(),
            NativeDomainId::mint(),
            |map: &mut FakeObjectMap, index, mut row| {
                if index == 21 {
                    row.action = OBJECT_ACTION_COPY;
                }
                FakeObjectMap::set(map, index, row)
            },
            FakeObjectMap::readback,
            FakeObjectMap::freeze,
        );
        assert!(matches!(result, Err(SemanticRefusal::Descriptor)));
    }

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
    fn identity_metadata_matches_embedded_native_objects() {
        let detailed = aya_obj::Object::parse(crate::EBPF_OBJECT).unwrap();
        for (name, expected) in IDENTITY_MAPS {
            let actual = detailed.maps.get(name).unwrap();
            assert_eq!(actual.map_type(), expected.map_type as u32, "{name} type");
            assert_eq!(actual.key_size(), expected.key_size, "{name} key");
            assert_eq!(actual.value_size(), expected.value_size, "{name} value");
            assert_eq!(actual.max_entries(), expected.max_entries, "{name} entries");
            assert_eq!(actual.map_flags(), expected.flags, "{name} flags");
        }
        let (_, detailed_owner) = IDENTITY_MAPS
            .iter()
            .find(|(name, _)| *name == "THREAD_OWNER")
            .unwrap();
        for bytes in [
            crate::EBPF_INVENTORY_OBJECT,
            crate::EBPF_INVENTORY_CALLERS_OBJECT,
        ] {
            let inventory = aya_obj::Object::parse(bytes).unwrap();
            let owner = inventory.maps.get("THREAD_OWNER").unwrap();
            assert_eq!(owner.value_size(), 544);
            let actual = map_metadata(
                MapType::TaskStorage,
                owner.key_size(),
                owner.value_size(),
                owner.max_entries(),
                owner.map_flags(),
            );
            assert!(compare_map_metadata("THREAD_OWNER", actual, *detailed_owner).is_err());
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

    fn terminal_fixture_payload(
        file: &std::fs::File,
        producer: ProducerProgram,
    ) -> (OwnedLink, ProducerProgram) {
        (
            OwnedLink::Multi(vec![file.try_clone().unwrap().into()]),
            producer,
        )
    }

    #[test]
    fn owner_terminal_hooks_registered_control_joins_actual_original_ownership() {
        let file = Arc::new(tempfile::tempfile().unwrap());
        let original = Arc::downgrade(&file);
        let worker = CleanupWorker::pre_start_with(
            Box::new(move |payload, _| {
                assert!(original.upgrade().unwrap().metadata().is_ok());
                drop(payload.take());
                Ok(())
            }),
            Arc::new(|| std::time::Duration::ZERO),
        );
        let mut source = Some(terminal_fixture_payload(
            &file,
            ProducerProgram::UProbe("p11_entry"),
        ));
        let mut calls = Vec::new();
        let mut failures = submit_terminal_ownership(&worker, Arc::new(vec![file]), |family| {
            calls.push(family);
            match family {
                TerminalProducerFamily::Registered => source.take().into_iter().map(Ok).collect(),
                TerminalProducerFamily::InstanceHooks => Vec::new(),
            }
        });
        let mut job = OwnedProducerDetach::Pending {
            worker,
            started: std::time::Instant::now(),
            had_work: true,
            progress: cleanup_worker::DetachPollPrinter::new(),
        };
        let mut detached = false;
        let mut out = Vec::new();
        job.drive(&mut failures, &mut detached, &mut 0, || false, &mut out)
            .unwrap();
        assert!(source.is_none() && detached);
        assert_eq!(
            calls
                .iter()
                .filter(|family| **family == TerminalProducerFamily::Registered)
                .count(),
            1
        );
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("1/1 links released")
        );
    }

    #[test]
    fn owner_terminal_hooks_all_original_owners_enter_the_same_receipt() {
        let file = Arc::new(tempfile::tempfile().unwrap());
        let original = Arc::downgrade(&file);
        let (entered, entered_rx) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let released = std::sync::Mutex::new(released);
        let closed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let close_log = Arc::clone(&closed);
        let worker = CleanupWorker::pre_start_with(
            Box::new(move |payload, program| {
                if matches!(program, ProducerProgram::InstanceHook(_)) {
                    let prior = close_log.lock().unwrap();
                    assert!(prior.contains(&ProducerProgram::UProbe("p11_return")));
                    assert!(
                        prior.contains(&ProducerProgram::RawTracePoint("sched_process_exit")),
                        "instance hooks retire after registered endpoint/lifecycle producers"
                    );
                    drop(prior);
                    entered.send(()).unwrap();
                    let _ = released
                        .lock()
                        .unwrap()
                        .recv_timeout(std::time::Duration::from_secs(5));
                }
                assert!(original.upgrade().unwrap().metadata().is_ok());
                drop(payload.take());
                close_log.lock().unwrap().push(program);
                Ok(())
            }),
            Arc::new(|| std::time::Duration::ZERO),
        );
        let mut registered = vec![
            terminal_fixture_payload(&file, ProducerProgram::UProbe("p11_entry")),
            terminal_fixture_payload(&file, ProducerProgram::UProbe("p11_return")),
            terminal_fixture_payload(&file, ProducerProgram::RawTracePoint("sched_process_exit")),
        ];
        let mut hooks: Vec<_> = INSTANCE_PROGRAMS
            .iter()
            .map(|(program, _)| {
                terminal_fixture_payload(&file, ProducerProgram::InstanceHook(program))
            })
            .collect();
        let mut failures = submit_terminal_ownership(&worker, Arc::new(vec![file]), |family| {
            std::mem::take(match family {
                TerminalProducerFamily::Registered => &mut registered,
                TerminalProducerFamily::InstanceHooks => &mut hooks,
            })
            .into_iter()
            .map(Ok)
            .collect()
        });
        let hook_started = entered_rx
            .recv_timeout(std::time::Duration::from_millis(200))
            .is_ok();
        let before = worker.progress();
        // Always release and actually join this owned worker before asserting,
        // including the current registered-only RED implementation.
        for _ in INSTANCE_PROGRAMS {
            let _ = release.send(());
        }
        let mut job = OwnedProducerDetach::Pending {
            worker,
            started: std::time::Instant::now(),
            had_work: true,
            progress: cleanup_worker::DetachPollPrinter::new(),
        };
        let mut detached = false;
        let mut out = Vec::new();
        let result = job.drive(&mut failures, &mut detached, &mut 0, || false, &mut out);
        assert!(
            hooks.is_empty(),
            "a completed worker cannot omit the four original instance-hook owners"
        );
        assert!(
            hook_started && before.released < before.total,
            "an actual hook close must remain unsettled until its leaf returns"
        );
        result.unwrap();
        assert!(detached);
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("7/7 links released")
        );
    }

    #[test]
    fn owner_terminal_hooks_partial_take_failure_cannot_claim_complete() {
        let file = Arc::new(tempfile::tempfile().unwrap());
        let worker = CleanupWorker::pre_start_with(
            Box::new(|payload, _| {
                drop(payload.take());
                Ok(())
            }),
            Arc::new(|| std::time::Duration::ZERO),
        );
        let mut registered = vec![terminal_fixture_payload(
            &file,
            ProducerProgram::UProbe("p11_entry"),
        )];
        let mut hooks: Vec<_> = INSTANCE_PROGRAMS
            .iter()
            .map(|(program, _)| {
                terminal_fixture_payload(&file, ProducerProgram::InstanceHook(program))
            })
            .collect();
        let mut refused_original = None;
        let mut failures = submit_terminal_ownership(&worker, Arc::new(vec![file]), |family| {
            if family == TerminalProducerFamily::Registered {
                return std::mem::take(&mut registered)
                    .into_iter()
                    .map(Ok)
                    .collect();
            }
            let mut outcomes: Vec<_> = std::mem::take(&mut hooks).into_iter().map(Ok).collect();
            let refused =
                std::mem::replace(&mut outcomes[1], Err(anyhow!("original hook take refused")));
            // Exactly as a failed Aya take: original owner remains in its
            // registry envelope; the worker never acquires that handle.
            refused_original = refused.ok();
            outcomes
        });
        let mut job = OwnedProducerDetach::Pending {
            worker,
            started: std::time::Instant::now(),
            had_work: true,
            progress: cleanup_worker::DetachPollPrinter::new(),
        };
        let mut detached = false;
        let mut out = Vec::new();
        let result = job.drive(&mut failures, &mut detached, &mut 0, || false, &mut out);
        assert!(
            result.is_err(),
            "one failed original hook take must refuse completed cleanup"
        );
        assert!(!detached && refused_original.is_some());
        let text = String::from_utf8(out).unwrap();
        assert!(
            text.contains("cleanup incomplete") && text.contains("1 uncertain"),
            "{text}"
        );
    }

    #[test]
    fn owner_terminal_prior_live_work_requires_the_original_joined_receipt() {
        let file = std::sync::Arc::new(tempfile::tempfile().unwrap());
        let original = std::sync::Arc::downgrade(&file);
        let worker = CleanupWorker::pre_start_with(
            Box::new(move |payload, _| {
                assert!(original.upgrade().unwrap().metadata().is_ok());
                drop(payload.take());
                Ok(())
            }),
            Arc::new(|| std::time::Duration::ZERO),
        );
        let ticket = worker
            .submit_live(
                vec![(
                    OwnedLink::Multi(vec![file.try_clone().unwrap().into()]),
                    ProducerProgram::UProbe("p11_entry"),
                )],
                Arc::new(vec![file]),
                DetachOrder,
            )
            .unwrap();
        assert!(worker.has_submissions());
        worker.begin_terminal();
        // The terminal batch can be empty while earlier actual live work
        // still belongs to this exact coordinator and receipt.
        worker.submit(Vec::new(), Arc::default(), DetachOrder);
        let mut job = OwnedProducerDetach::Pending {
            worker,
            started: std::time::Instant::now(),
            had_work: true,
            progress: cleanup_worker::DetachPollPrinter::new(),
        };
        let mut detached = false;
        let mut failures = Vec::new();
        let mut wall = 0;
        let mut out = Vec::new();
        job.drive(&mut failures, &mut detached, &mut wall, || false, &mut out)
            .unwrap();
        assert!(detached && matches!(job, OwnedProducerDetach::Complete));
        assert!(
            String::from_utf8(out.clone())
                .unwrap()
                .contains("1/1 links released")
        );
        job.drive(&mut failures, &mut detached, &mut wall, || true, &mut out)
            .unwrap();
        assert_eq!(
            String::from_utf8(out)
                .unwrap()
                .matches("cleanup completed")
                .count(),
            1
        );
        drop(ticket);
    }

    #[test]
    fn selected_cleanup_poll_keeps_blocked_original_worker_until_joined_receipt() {
        let (release, released) = std::sync::mpsc::channel();
        let released = std::sync::Mutex::new(released);
        let (entered, entered_rx) = std::sync::mpsc::channel();
        let worker = CleanupWorker::pre_start_with(
            Box::new(move |payload, _| {
                entered.send(()).unwrap();
                released
                    .lock()
                    .unwrap()
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                drop(payload.take());
                Ok(())
            }),
            Arc::new(|| std::time::Duration::ZERO),
        );
        worker.submit(
            vec![(
                OwnedLink::Multi(Vec::new()),
                ProducerProgram::UProbe("p11_entry"),
            )],
            Arc::default(),
            DetachOrder,
        );
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        let mut job = OwnedProducerDetach::Pending {
            worker,
            started: std::time::Instant::now(),
            had_work: true,
            progress: cleanup_worker::DetachPollPrinter::new(),
        };
        for _ in 0..4 {
            assert!(
                !job.ready_to_finish(),
                "started close cannot grant settlement"
            );
            assert!(matches!(job, OwnedProducerDetach::Pending { .. }));
        }
        release.send(()).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !job.ready_to_finish() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        assert!(
            matches!(job, OwnedProducerDetach::Pending { .. }),
            "readiness must not consume job"
        );
        let mut detached = false;
        job.drive(
            &mut Vec::new(),
            &mut detached,
            &mut 0,
            || false,
            &mut std::io::sink(),
        )
        .unwrap();
        assert!(detached && matches!(job, OwnedProducerDetach::Complete));
    }

    #[test]
    fn owned_detach_poll_preserves_original_worker_and_leases() {
        // A poll before begin is refused without consuming: the Session
        // can still begin its owned detach afterwards.
        let mut idle = OwnedProducerDetach::NotStarted;
        let mut failures = Vec::new();
        let mut detached = false;
        let mut wall = 0;
        let error = idle
            .poll(
                &mut failures,
                &mut detached,
                &mut wall,
                &mut std::io::sink(),
            )
            .expect_err("a poll before begin is refused");
        assert_eq!(format!("{error:#}"), "owned producer detach not begun");
        assert!(
            matches!(idle, OwnedProducerDetach::NotStarted),
            "a refused poll keeps NotStarted for the later begin"
        );
        assert!(!detached && failures.is_empty());

        // A real worker with a blocked closer and a real lease file.
        let file = Arc::new(tempfile::tempfile().unwrap());
        let lease = Arc::downgrade(&file);
        let mut source = Some(terminal_fixture_payload(
            &file,
            ProducerProgram::UProbe("p11_entry"),
        ));
        let (release, released) = std::sync::mpsc::channel();
        let released = std::sync::Mutex::new(released);
        let (entered, entered_rx) = std::sync::mpsc::channel();
        let worker = CleanupWorker::pre_start_with(
            Box::new(move |payload, _| {
                entered.send(()).unwrap();
                released
                    .lock()
                    .unwrap()
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .unwrap();
                drop(payload.take());
                Ok(())
            }),
            Arc::new(|| std::time::Duration::ZERO),
        );
        worker.submit(
            source.take().into_iter().collect(),
            Arc::new(vec![file]),
            DetachOrder,
        );
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        let mut job = OwnedProducerDetach::Pending {
            worker,
            started: std::time::Instant::now(),
            had_work: true,
            progress: cleanup_worker::DetachPollPrinter::new(),
        };
        let original = match &job {
            OwnedProducerDetach::Pending { worker, .. } => worker.original_thread_id(),
            _ => None,
        };
        assert!(original.is_some(), "the owned worker thread is prestarted");
        assert!(source.is_none());
        for _ in 0..3 {
            let progress = job
                .poll(
                    &mut failures,
                    &mut detached,
                    &mut wall,
                    &mut std::io::sink(),
                )
                .unwrap();
            assert!(
                matches!(progress, ProducerDetachProgress::Pending),
                "a blocked close keeps the owned detach pending"
            );
            match &job {
                OwnedProducerDetach::Pending { worker, .. } => assert_eq!(
                    worker.original_thread_id(),
                    original,
                    "a pending poll keeps the SAME worker thread"
                ),
                _ => panic!("a pending poll must not consume the owned job"),
            }
            assert!(!detached && failures.is_empty());
            assert!(
                lease.upgrade().is_some_and(|file| file.metadata().is_ok()),
                "a pending poll keeps the original leases"
            );
        }
        release.send(()).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let progress = job
                .poll(
                    &mut failures,
                    &mut detached,
                    &mut wall,
                    &mut std::io::sink(),
                )
                .unwrap();
            if matches!(progress, ProducerDetachProgress::Complete) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the released close must settle"
            );
            std::thread::yield_now();
        }
        assert!(detached && failures.is_empty());
        assert!(matches!(job, OwnedProducerDetach::Complete));
        // Completion is idempotent: a settled poll stays settled.
        let progress = job
            .poll(
                &mut failures,
                &mut detached,
                &mut wall,
                &mut std::io::sink(),
            )
            .unwrap();
        assert!(matches!(progress, ProducerDetachProgress::Complete));
        assert!(detached && matches!(job, OwnedProducerDetach::Complete));

        // An unproved job stays unproved and refuses idempotently.
        let mut job = OwnedProducerDetach::Unproved;
        let mut detached = false;
        assert!(
            job.poll(
                &mut failures,
                &mut detached,
                &mut wall,
                &mut std::io::sink()
            )
            .is_err(),
            "an unproved poll stays a refusal"
        );
        assert!(!detached && matches!(job, OwnedProducerDetach::Unproved));
    }

    /// A gated detach job over `singles` single links with a scripted
    /// worker clock: polls stay Pending until one release per link.
    fn gated_detach_job(
        singles: usize,
    ) -> (
        OwnedProducerDetach,
        Arc<std::sync::Mutex<std::time::Duration>>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (release, released) = std::sync::mpsc::channel();
        let released = std::sync::Mutex::new(released);
        let now = Arc::new(std::sync::Mutex::new(std::time::Duration::ZERO));
        let worker_now = Arc::clone(&now);
        let worker = CleanupWorker::pre_start_with(
            Box::new(move |payload, _| {
                released
                    .lock()
                    .unwrap()
                    .recv()
                    .expect("one release per link");
                drop(payload.take());
                Ok(())
            }),
            Arc::new(move || *worker_now.lock().unwrap()),
        );
        worker.submit(
            (0..singles)
                .map(|_| (OwnedLink::TestSingle, ProducerProgram::UProbe("p11_entry")))
                .collect(),
            Arc::default(),
            DetachOrder,
        );
        let job = OwnedProducerDetach::Pending {
            worker,
            started: std::time::Instant::now(),
            had_work: true,
            progress: cleanup_worker::DetachPollPrinter::new(),
        };
        (job, now, release)
    }

    #[test]
    fn owned_detach_poll_writes_stop_estimate_once_and_progress_on_cadence() {
        let (mut job, now, release) = gated_detach_job(40);
        let mut failures = Vec::new();
        let mut detached = false;
        let mut wall_ms = 0;
        let mut out = Vec::new();
        // The first pending poll prints only the one-shot estimate.
        let progress = job
            .poll(&mut failures, &mut detached, &mut wall_ms, &mut out)
            .unwrap();
        assert!(
            matches!(progress, ProducerDetachProgress::Pending),
            "a gated close stays pending"
        );
        assert_eq!(
            String::from_utf8(out.clone()).expect("progress lines are UTF-8"),
            "p11scope: closing 40 probe links one at a time (no batched uprobe detach on this kernel); about 2 s, progress follows\n",
            "the first pending poll prints only the one-shot estimate"
        );
        // Half a second in: still no progress line.
        *now.lock().unwrap() = std::time::Duration::from_millis(500);
        let progress = job
            .poll(&mut failures, &mut detached, &mut wall_ms, &mut out)
            .unwrap();
        assert!(
            matches!(progress, ProducerDetachProgress::Pending),
            "a gated close stays pending"
        );
        let text = String::from_utf8(out.clone()).expect("progress lines are UTF-8");
        assert!(
            !text.contains("cleanup "),
            "no progress before the 1 s cadence: {text:?}"
        );
        // Past one second: the progress line follows, the estimate
        // stays one-shot.
        *now.lock().unwrap() = std::time::Duration::from_secs(2);
        let progress = job
            .poll(&mut failures, &mut detached, &mut wall_ms, &mut out)
            .unwrap();
        assert!(
            matches!(progress, ProducerDetachProgress::Pending),
            "a gated close stays pending"
        );
        let text = String::from_utf8(out.clone()).expect("progress lines are UTF-8");
        assert!(
            text.contains("p11scope: cleanup 0/40 links released, 2 s\n"),
            "progress follows on cadence: {text:?}"
        );
        assert_eq!(
            text.matches("probe links one at a time").count(),
            1,
            "the estimate stays one-shot"
        );
        // Same second: no duplicate progress.
        let progress = job
            .poll(&mut failures, &mut detached, &mut wall_ms, &mut out)
            .unwrap();
        assert!(
            matches!(progress, ProducerDetachProgress::Pending),
            "a gated close stays pending"
        );
        let text = String::from_utf8(out.clone()).expect("progress lines are UTF-8");
        assert_eq!(
            text.matches("cleanup ").count(),
            1,
            "no duplicate within the cadence"
        );
        // Release every link and drain to completion (bounded).
        for _ in 0..40 {
            release.send(()).unwrap();
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let progress = job
                .poll(&mut failures, &mut detached, &mut wall_ms, &mut out)
                .unwrap();
            if matches!(progress, ProducerDetachProgress::Complete) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the released close must settle"
            );
            std::thread::yield_now();
        }
        assert!(matches!(job, OwnedProducerDetach::Complete));
        let text = String::from_utf8(out.clone()).expect("progress lines are UTF-8");
        assert_eq!(
            text.matches("probe links one at a time").count(),
            1,
            "one estimate per stop"
        );
        assert_eq!(
            text.matches("cleanup ").count(),
            1,
            "the drain prints no further progress at the same clock"
        );
    }

    #[test]
    fn owned_detach_poll_writes_no_estimate_below_two_second_floor() {
        let (mut job, now, release) = gated_detach_job(1);
        let mut failures = Vec::new();
        let mut detached = false;
        let mut wall_ms = 0;
        let mut out = Vec::new();
        // Below the floor and the cadence: silent.
        let progress = job
            .poll(&mut failures, &mut detached, &mut wall_ms, &mut out)
            .unwrap();
        assert!(
            matches!(progress, ProducerDetachProgress::Pending),
            "a gated close stays pending"
        );
        let text = String::from_utf8(out.clone()).expect("progress lines are UTF-8");
        assert!(text.is_empty(), "a quick stop stays silent: {text:?}");
        // Past one second: progress follows, still no estimate.
        *now.lock().unwrap() = std::time::Duration::from_secs(2);
        let progress = job
            .poll(&mut failures, &mut detached, &mut wall_ms, &mut out)
            .unwrap();
        assert!(
            matches!(progress, ProducerDetachProgress::Pending),
            "a gated close stays pending"
        );
        let text = String::from_utf8(out.clone()).expect("progress lines are UTF-8");
        assert!(
            text.contains("p11scope: cleanup 0/1 links released, 2 s\n"),
            "progress follows on cadence: {text:?}"
        );
        assert!(
            !text.contains("probe links one at a time"),
            "no estimate below the 2 s floor: {text:?}"
        );
        // Release the link and drain to completion (bounded).
        release.send(()).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            let progress = job
                .poll(&mut failures, &mut detached, &mut wall_ms, &mut out)
                .unwrap();
            if matches!(progress, ProducerDetachProgress::Complete) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the released close must settle"
            );
            std::thread::yield_now();
        }
        assert!(matches!(job, OwnedProducerDetach::Complete));
        let text = String::from_utf8(out.clone()).expect("progress lines are UTF-8");
        assert!(
            !text.contains("probe links one at a time"),
            "no estimate below the 2 s floor: {text:?}"
        );
    }

    #[test]
    fn owner_terminal_interrupted_job_cannot_turn_empty_into_success() {
        let (release, released) = std::sync::mpsc::channel();
        let released = std::sync::Mutex::new(released);
        let (entered, entered_rx) = std::sync::mpsc::channel();
        let (done, done_rx) = std::sync::mpsc::channel();
        let worker = CleanupWorker::pre_start_with_spawn(
            Box::new(move |payload, _| {
                entered.send(()).unwrap();
                let _ = released
                    .lock()
                    .unwrap()
                    .recv_timeout(std::time::Duration::from_secs(5));
                drop(payload.take());
                Ok(())
            }),
            Arc::new(|| std::time::Duration::ZERO),
            |task| {
                Ok(std::thread::spawn(move || {
                    task();
                    let _ = done.send(());
                }))
            },
        );
        worker.submit(
            vec![(
                OwnedLink::Multi(vec![tempfile::tempfile().unwrap().into()]),
                ProducerProgram::UProbe("p11_return"),
            )],
            Arc::default(),
            DetachOrder,
        );
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let progress = worker.progress();
        assert_eq!(
            (progress.attempted, progress.released, progress.remaining),
            (1, 0, 0)
        );
        let mut job = OwnedProducerDetach::Pending {
            worker,
            started: std::time::Instant::now(),
            had_work: true,
            progress: cleanup_worker::DetachPollPrinter::new(),
        };
        let mut detached = false;
        let mut failures = Vec::new();
        let mut wall = 0;
        let result = job.drive(
            &mut failures,
            &mut detached,
            &mut wall,
            || true,
            &mut Vec::new(),
        );
        // Drain every actual test-owned close/coordinator before asserting.
        release.send(()).unwrap();
        done_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert!(result.unwrap_err().is::<CleanupInterrupted>());
        assert!(!detached && matches!(job, OwnedProducerDetach::Unproved));
        assert!(
            job.drive(
                &mut failures,
                &mut detached,
                &mut wall,
                || false,
                &mut Vec::new()
            )
            .is_err()
        );
        assert!(!detached);
        assert!(
            !job.ready_to_finish(),
            "abandoned cleanup cannot become retry permission"
        );
    }

    #[test]
    fn owner_terminal_partial_transfer_and_close_failure_stay_unproved() {
        for mode in 0..3 {
            let worker = CleanupWorker::pre_start_with(
                Box::new(move |payload, _| {
                    drop(payload.take());
                    match mode {
                        0 => Ok(()),
                        1 => Err("injected close failure".into()),
                        _ => panic!("injected close panic"),
                    }
                }),
                Arc::new(|| std::time::Duration::ZERO),
            );
            let mut failures = Vec::new();
            if mode == 0 {
                worker.note_transfer_failed(1);
                failures.push("original Aya registry transfer refused".into());
            }
            worker.submit(
                vec![(
                    OwnedLink::Multi(Vec::new()),
                    ProducerProgram::UProbe("p11_entry"),
                )],
                Arc::default(),
                DetachOrder,
            );
            let mut job = OwnedProducerDetach::Pending {
                worker,
                started: std::time::Instant::now(),
                had_work: true,
                progress: cleanup_worker::DetachPollPrinter::new(),
            };
            let mut detached = false;
            let mut wall = 0;
            assert!(
                job.drive(
                    &mut failures,
                    &mut detached,
                    &mut wall,
                    || false,
                    &mut Vec::new()
                )
                .is_err()
            );
            assert!(!detached && !failures.is_empty());
            assert!(
                job.drive(
                    &mut failures,
                    &mut detached,
                    &mut wall,
                    || false,
                    &mut Vec::new()
                )
                .is_err()
            );
            assert!(!detached);
        }
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
            PublishObjects,
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
            FreezeDeferred("OBJECT_DESCRIPTORS"),
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
            let preparation = prepare_session_with(unsafe_object, StaticRoots::Detailed, |step| {
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
                assert_eq!(deferred_frozen.get(), 3);
                activation_called.set(true);
                Ok(())
            })
            .unwrap();
            assert!(activation_called.get());
        }
    }

    #[test]
    fn counter_program_load_precedes_deferred_freeze_and_activation() {
        for roots in [StaticRoots::Detailed, StaticRoots::CounterBanks] {
            for fail_counter in [false, true] {
                let mut seen = Vec::new();
                let mut activated = false;
                let preparation = prepare_session_with(false, roots, |step| {
                    if step == SessionPreparation::LoadCounterPrograms {
                        anyhow::ensure!(
                            !seen.iter().any(|step| matches!(
                                step,
                                SessionPreparation::FreezeDeferred(_)
                                    | SessionPreparation::PublishTailCalls
                            )),
                            "counter roots must load before readonly policy freezes"
                        );
                    }
                    seen.push(step);
                    if fail_counter && step == SessionPreparation::LoadCounterPrograms {
                        anyhow::bail!("injected counter root load failure");
                    }
                    Ok(())
                });
                let result = activate_after_preparation_with(preparation, || {
                    activated = true;
                    Ok(())
                });
                if roots == StaticRoots::CounterBanks {
                    let load = seen
                        .iter()
                        .position(|step| *step == SessionPreparation::LoadCounterPrograms)
                        .unwrap();
                    assert_eq!(
                        seen.iter()
                            .filter(|step| { **step == SessionPreparation::LoadCounterPrograms })
                            .count(),
                        1
                    );
                    if fail_counter {
                        assert!(result.is_err());
                        assert!(!activated);
                        assert_eq!(seen.last(), Some(&SessionPreparation::LoadCounterPrograms));
                    } else {
                        result.unwrap();
                        assert!(activated);
                        let freeze = seen
                            .iter()
                            .position(|step| matches!(step, SessionPreparation::FreezeDeferred(_)))
                            .unwrap();
                        assert!(load < freeze);
                    }
                } else {
                    result.unwrap();
                    assert!(activated);
                    assert_eq!(seen, expected_preparation(false));
                }
            }
        }
    }

    #[test]
    fn preparation_contract_runs_every_phase_successfully() {
        for unsafe_object in [false, true] {
            let mut seen = Vec::new();
            prepare_session_with(unsafe_object, StaticRoots::Detailed, |step| {
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
            let preparation_result =
                prepare_session_with(unsafe_object, StaticRoots::Detailed, |step| {
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
                let preparation_result =
                    prepare_session_with(unsafe_object, StaticRoots::Detailed, |step| {
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
            let preparation =
                prepare_session_with(unsafe_object, StaticRoots::Detailed, |_| Ok(()));
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
        assert_eq!(
            deferred,
            [
                "CONFIG",
                "DESCRIPTORS",
                TAIL_POLICY_MAP,
                "OBJECT_DESCRIPTORS"
            ]
        );
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
    fn counter_bank_multi_diagnostics_stay_within_precharged_utf8_bound() {
        let path = Path::new("/proc/self/fd/2147483647");
        for program in ["p11_counter_bank_entry", "p11_counter_bank_return"] {
            for errno in [i32::MIN, libc::EMFILE, i32::MAX] {
                let message = group_site_failure(
                    program,
                    path,
                    u64::MAX,
                    &io::Error::from_raw_os_error(errno),
                );
                assert!(message.starts_with(program));
                assert!(message.contains("/proc/self/fd/2147483647+0xffffffffffffffff"));
                assert!(message.ends_with(&format!("errno {errno}")));
                assert!(message.len() <= COUNTER_GROUP_DIAGNOSTIC_BYTES);
                assert!(message.capacity() <= COUNTER_GROUP_DIAGNOSTIC_BYTES);
            }
            let error = io::Error::other("界".repeat(COUNTER_GROUP_DIAGNOSTIC_BYTES));
            let message = group_site_failure(program, Path::new("/tmp/界.so"), 7, &error);
            assert!(message.contains("<invalid FD path>+0x7: errno unavailable"));
            assert!(!message.contains('界'));
            assert!(message.len() <= COUNTER_GROUP_DIAGNOSTIC_BYTES);
            assert!(message.capacity() <= COUNTER_GROUP_DIAGNOSTIC_BYTES);
            assert!(!counter_attach_path_is_valid(Path::new("/tmp/界.so")));
            assert!(!counter_attach_path_is_valid(Path::new(
                "/proc/self/fd/12345678901"
            )));
        }
        // These unchanged exhaustion messages also enter Counts' retained
        // failures. Include their actual format capacity, not only text length.
        for (_, message) in [
            unfinished_after_exhaustion(u32::MAX),
            exhausted_multi(u32::MAX, usize::MAX, usize::MAX),
        ] {
            assert!(message.len() <= COUNTER_GROUP_DIAGNOSTIC_BYTES);
            assert!(message.capacity() <= COUNTER_GROUP_DIAGNOSTIC_BYTES);
        }
        // Detailed keeps the original path and complete error text, including
        // UTF-8 byte growth. The bounded format belongs only to Counts roots.
        let error = io::Error::other("provider 界 failure");
        assert_eq!(
            group_site_failure("p11_return", Path::new("/tmp/界.so"), 0x123, &error),
            "p11_return at /tmp/界.so+0x123: provider 界 failure"
        );
    }

    // Exercise actual grouping and registered ownership with real file FDs.
    // Matching kernel-link qualification remains in the separate native cells.
    #[test]
    fn counter_bank_multi_groups_use_fixed_roots_and_exact_cookies() {
        let (_fixture, pins, mut first, mut second, _) =
            counter_banks::tests::growth_provider_fixture();
        first.index = 511;
        first.descriptor_index = 17;
        first.file_offset = 0x80;
        second.index = 512;
        second.descriptor_index = 18;
        second.file_offset = 0x90;
        let mut third = first.clone();
        third.index = 513;
        third.descriptor_index = 19;
        third.file_offset = 0xa0;
        let slots = vec![second, third, first];
        let targets: BTreeMap<_, _> = slots
            .iter()
            .map(|slot| {
                (
                    slot.index,
                    (
                        pins.attach_path_for(slot.object).unwrap(),
                        pins.abi_for(slot.object).unwrap(),
                    ),
                )
            })
            .collect();
        let groups: Vec<StaticGroup> = group_static_slots_with_roots(
            &slots,
            CapturePolicy::AggregateOnly,
            false,
            &targets,
            StaticRoots::CounterBanks,
        )
        .unwrap();
        assert_eq!(groups.len(), 2);
        assert!(
            groups
                .iter()
                .all(|group| group.entry_program == "p11_counter_bank_entry"
                    && group.return_program == "p11_counter_bank_return")
        );
        type RecordedMultiCall = (&'static str, Vec<(u64, u64)>, bool);
        let mut calls: Vec<RecordedMultiCall> = Vec::new();
        let (bundles, outcome) = attach_target_groups_with(
            &groups,
            |_| Some(7),
            |program, _, sites, is_return| {
                calls.push((program, sites.to_vec(), is_return));
                Ok(tempfile::tempfile().unwrap().into())
            },
        )
        .unwrap();
        let _: &Vec<MultiLinkBundle<OwnedFd>> = &bundles;
        assert_eq!(calls.len(), 4);
        for pair in calls.as_chunks::<2>().0 {
            assert_eq!((pair[0].0, pair[0].2), ("p11_counter_bank_return", true));
            assert_eq!((pair[1].0, pair[1].2), ("p11_counter_bank_entry", false));
            assert_eq!(pair[0].1, pair[1].1);
        }
        let mut sites: Vec<_> = calls
            .iter()
            .filter(|call| !call.2)
            .flat_map(|call| call.1.iter().copied())
            .collect();
        sites.sort_unstable_by_key(|site| site.1);
        assert_eq!(
            sites,
            [
                (0x80, 0x0000_0011_0000_01ff),
                (0x90, 0x0000_0012_0000_0200),
                (0xa0, 0x0000_0013_0000_0201),
            ]
        );
        let mut completed: Vec<_> = outcome.completed.iter().map(|(index, _)| *index).collect();
        completed.sort_unstable();
        assert_eq!(
            completed,
            [511, 512, 513],
            "each original slot is acknowledged exactly once"
        );
        assert_eq!(outcome.successful.len(), 6);
        assert!(outcome.failures.is_empty() && !outcome.exhausted);
        let mut links: Vec<RegisteredLink> = Vec::new();
        let mut pairs = pid_continuity::PairBook::default();
        let reserved: Result<(), counter_banks::BankRefusal> =
            reserve_counter_multi_link_capacity(&mut links, 1);
        reserved.unwrap();
        let called = std::cell::Cell::new(false);
        let invalid: io::Result<()> = retain_counter_multi_leaf(
            &mut links,
            &mut pairs,
            "p11_counter_bank_return",
            &[(0x80, 0x0000_0011_0000_01ff)],
            &BTreeMap::new(),
            || {
                called.set(true);
                Ok(tempfile::tempfile().unwrap().into())
            },
        );
        assert!(
            invalid.is_err() && !called.get() && links.is_empty(),
            "unknown cookie refuses before the native leaf"
        );
        for (policy, unsafe_object, bad_abi) in [
            (CapturePolicy::Allowlisted, false, false),
            (CapturePolicy::AggregateOnly, true, false),
            (CapturePolicy::AggregateOnly, false, true),
        ] {
            let mut target_facts = targets.clone();
            if bad_abi {
                target_facts.get_mut(&511).unwrap().1 = ElfAbi::Ilp32;
            }
            let refused: Result<Vec<StaticGroup>> = group_static_slots_with_roots(
                &slots,
                policy,
                unsafe_object,
                &target_facts,
                StaticRoots::CounterBanks,
            );
            assert!(refused.is_err());
        }
        let detailed = group_static_slots(&slots, CapturePolicy::AggregateOnly, false, &targets);
        assert!(
            detailed
                .iter()
                .all(|group| group.entry_program == "p11_entry")
        );
    }

    #[test]
    fn counter_bank_multi_append_and_late_failure_preserve_old_groups() {
        for refusal in [None, Some(libc::EOPNOTSUPP), Some(libc::EMFILE)] {
            let (_fixture, pins, first, mut second, _) =
                counter_banks::tests::growth_provider_fixture();
            let old_slots: Vec<_> = (0..511)
                .map(|index| {
                    let mut slot = first.clone();
                    slot.index = index;
                    slot.file_offset = 0x1000 + 16 * u64::from(index);
                    slot
                })
                .collect();
            let mut addition = first.clone();
            addition.index = 511;
            addition.file_offset = 0x1000 + 16 * 511;
            second.index = 512;
            second.file_offset = 0x1000;
            let fresh = vec![addition, second];
            let all_targets: BTreeMap<_, _> = old_slots
                .iter()
                .chain(&fresh)
                .map(|slot| {
                    (
                        slot.index,
                        (
                            pins.attach_path_for(slot.object).unwrap(),
                            pins.abi_for(slot.object).unwrap(),
                        ),
                    )
                })
                .collect();
            let old_groups: Vec<StaticGroup> = group_static_slots_with_roots(
                &old_slots,
                CapturePolicy::AggregateOnly,
                false,
                &all_targets,
                StaticRoots::CounterBanks,
            )
            .unwrap();
            let fresh_groups: Vec<StaticGroup> = group_static_slots_with_roots(
                &fresh,
                CapturePolicy::AggregateOnly,
                false,
                &all_targets,
                StaticRoots::CounterBanks,
            )
            .unwrap();
            assert_eq!(old_groups.len(), 1);
            assert_eq!(fresh_groups.len(), 2);
            let mut links: Vec<RegisteredLink> = Vec::new();
            let mut pairs = pid_continuity::PairBook::default();
            let reserved: Result<(), counter_banks::BankRefusal> =
                reserve_counter_multi_link_capacity(&mut links, old_slots.len());
            reserved.unwrap();
            let old_index: BTreeMap<_, _> = old_groups
                .iter()
                .flat_map(|group| &group.members)
                .map(|member| (member.cookie, member.slot.index))
                .collect();
            let (_, old_outcome): (Vec<MultiLinkBundle<()>>, AttachOutcome) =
                attach_target_groups_with(
                    &old_groups,
                    |_| Some(1),
                    |program, _, sites, _| {
                        retain_counter_multi_leaf(
                            &mut links,
                            &mut pairs,
                            program,
                            sites,
                            &old_index,
                            || Ok(tempfile::tempfile().unwrap().into()),
                        )
                    },
                )
                .unwrap();
            assert_eq!(old_outcome.completed.len(), 511);
            assert_eq!(links.len(), 2);
            let original_fds: Vec<_> = links
                .iter()
                .flat_map(|link| match link {
                    RegisteredLink::MultiUProbe { fds, .. } => fds
                        .iter()
                        .map(std::os::fd::AsRawFd::as_raw_fd)
                        .collect::<Vec<_>>(),
                    _ => unreachable!(),
                })
                .collect();
            let old_members: Vec<u32> = (0..511).collect();
            assert!(
                links
                    .iter()
                    .all(|link| link.slots() == old_members.as_slice())
            );
            let reserved: Result<(), counter_banks::BankRefusal> =
                reserve_counter_multi_link_capacity(&mut links, fresh.len());
            reserved.unwrap();
            let fresh_index: BTreeMap<_, _> = fresh_groups
                .iter()
                .flat_map(|group| &group.members)
                .map(|member| (member.cookie, member.slot.index))
                .collect();
            let mut native_calls = 0;
            let outcome: Result<
                (Vec<MultiLinkBundle<()>>, AttachOutcome),
                BackendFallbackRequired,
            > = attach_target_groups_with(
                &fresh_groups,
                |_| Some(2),
                |program, _, sites, _| {
                    assert!(sites.iter().all(|(_, cookie)| {
                        fresh_index
                            .get(cookie)
                            .is_some_and(|slot| matches!(*slot, 511 | 512))
                    }));
                    retain_counter_multi_leaf(
                        &mut links,
                        &mut pairs,
                        program,
                        sites,
                        &fresh_index,
                        || {
                            native_calls += 1;
                            if native_calls == 3
                                && let Some(errno) = refusal
                            {
                                Err(io::Error::from_raw_os_error(errno))
                            } else {
                                Ok(tempfile::tempfile().unwrap().into())
                            }
                        },
                    )
                },
            );
            match refusal {
                None => {
                    let (_, outcome) = outcome.unwrap();
                    let completed: BTreeSet<_> = outcome
                        .completed
                        .into_iter()
                        .map(|(index, _)| index)
                        .collect();
                    assert_eq!(completed, BTreeSet::from([511, 512]));
                    assert!(!outcome.exhausted && outcome.failures.is_empty());
                    assert_eq!(links.len(), 6);
                }
                Some(libc::EMFILE) => {
                    let (_, outcome) = outcome.unwrap();
                    assert!(outcome.exhausted);
                    assert_eq!(
                        links.len(),
                        4,
                        "the successful fresh return/entry leaves remain owned"
                    );
                }
                Some(_) => {
                    assert!(outcome.is_err());
                    assert_eq!(
                        links.len(),
                        4,
                        "late Unsupported cannot drop earlier acquired leaves inline"
                    );
                }
            }
            assert!(
                original_fds
                    .iter()
                    .all(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0)
            );
            assert!(
                links[..2]
                    .iter()
                    .all(|link| link.slots() == old_members.as_slice())
            );
            let requested = BTreeSet::from([511, 512]);
            let candidate_check: Result<()> = validate_counter_group_retirement(&links, &requested);
            candidate_check.unwrap();
            let selected = extract_selected_links(&mut links, &mut pairs, |link| {
                link.slots().iter().any(|slot| requested.contains(slot))
            });
            let selected = selected
                .into_iter()
                .map(|link| (link.producer(), link))
                .collect();
            let mut closed = Vec::new();
            let failures = detach_selected_with(selected, |link: RegisteredLink| {
                closed.push(link.producer());
                drop(link);
                Ok(())
            });
            assert!(failures.is_empty());
            assert!(closed.windows(2).all(|pair| !matches!(
                pair,
                [
                    ProducerProgram::UProbe("p11_counter_bank_return"),
                    ProducerProgram::UProbe("p11_counter_bank_entry")
                ]
            )));
            assert_eq!(links.len(), 2);
            assert!(
                links
                    .iter()
                    .all(|link| link.slots() == old_members.as_slice())
            );
            assert!(
                original_fds
                    .iter()
                    .all(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0)
            );
        }
    }

    #[test]
    fn counter_bank_multi_refuses_partial_published_rebuild() {
        let mut pairs = pid_continuity::PairBook::default();
        let mut links: Vec<_> = ["p11_counter_bank_return", "p11_counter_bank_entry"]
            .into_iter()
            .map(|program| RegisteredLink::MultiUProbe {
                program,
                slots: vec![0, 1],
                fds: vec![tempfile::tempfile().unwrap().into()],
                registration: pairs.register(),
            })
            .collect();
        let original_fds: Vec<_> = links
            .iter()
            .flat_map(|link| match link {
                RegisteredLink::MultiUProbe { fds, .. } => fds
                    .iter()
                    .map(std::os::fd::AsRawFd::as_raw_fd)
                    .collect::<Vec<_>>(),
                _ => unreachable!(),
            })
            .collect();
        let partial: Result<()> = validate_counter_group_retirement(&links, &BTreeSet::from([1]));
        assert!(partial.is_err());
        assert_eq!(links.len(), 2);
        assert!(links.iter().all(|link| link.slots() == [0, 1]));
        assert!(
            original_fds
                .iter()
                .all(|fd| unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0)
        );
        let whole: Result<()> = validate_counter_group_retirement(&links, &BTreeSet::from([0, 1]));
        whole.unwrap();
        let selected = extract_selected_links(&mut links, &mut pairs, |_| true);
        let mut closed = Vec::new();
        assert!(
            detach_selected_with(
                selected
                    .into_iter()
                    .map(|link| (link.producer(), link))
                    .collect(),
                |link: RegisteredLink| {
                    closed.push(link.producer());
                    drop(link);
                    Ok(())
                }
            )
            .is_empty()
        );
        assert_eq!(
            closed,
            [
                ProducerProgram::UProbe("p11_counter_bank_entry"),
                ProducerProgram::UProbe("p11_counter_bank_return")
            ]
        );
        assert!(links.is_empty());
        let mut links = Vec::new();
        let overflow: Result<(), counter_banks::BankRefusal> =
            reserve_counter_multi_link_capacity(&mut links, usize::MAX);
        assert!(overflow.is_err());
        assert_eq!(
            links.capacity(),
            0,
            "overflow refuses before registry allocation"
        );
    }

    #[test]
    fn selected_multi_late_unsupported_keeps_every_acquired_group_fd() {
        for fail_second_group in [false, true] {
            let (slots, targets) = two_groups();
            let groups = group_static_slots(&slots, CapturePolicy::Allowlisted, false, &targets);
            let mut retained: Vec<OwnedFd> = Vec::new();
            let result = attach_target_groups_with(
                &groups,
                |_| Some(7),
                |_, path, _, is_return| {
                    let refuse = if fail_second_group {
                        path == Path::new("/b.so") && is_return
                    } else {
                        !is_return
                    };
                    let acquired = if refuse {
                        Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
                    } else {
                        Ok(tempfile::tempfile().unwrap().into())
                    };
                    selected_detailed::multi::retain_success(acquired, |fd| retained.push(fd))
                },
            );
            assert!(
                result.is_err(),
                "real group orchestration must return fallback sentinel"
            );
            assert_eq!(retained.len(), if fail_second_group { 2 } else { 1 });
            assert!(
                retained
                    .iter()
                    .all(|fd| unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } >= 0),
                "later group failure must leave acquired native fds with their original owner"
            );
            // The preparation failure transfers this same retained Session to
            // actual terminal cleanup; this test grants no joined receipt.
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
            registration: None,
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
        RetainedStaticTarget {
            slot,
            path,
            abi,
            held: None,
        }
    }

    #[test]
    fn pid_continuity_attach_start_precedes_first_return_and_completion() {
        use pid_continuity::{AttachBaseline, NativeAttempt, PairBook};
        let (_dir, pins, target) = pid_continuity::tests::fixture();
        let mut sibling = target.clone();
        sibling.slot.index = 1;
        sibling.slot.file_offset += 8;
        let slots = [target.slot.clone(), sibling.slot.clone()];
        let retained = BTreeMap::from([(0, target), (1, sibling)]);
        let mut pairs = PairBook::default();
        let mut links = Vec::new();
        let times = std::cell::RefCell::new(std::collections::VecDeque::from([10, 20, 40, 50]));
        let calls = std::cell::RefCell::new(Vec::new());
        let outcome = attach_targets_observed_with(&slots, CapturePolicy::AggregateOnly, false,
            |_| Ok(ElfAbi::Lp64),
            |program, slot, point| NativeAttempt::run(|| times.borrow_mut().pop_front(), || {
                assert!(matches!(point.location, UProbeAttachLocation::AbsoluteOffset(offset) if offset == slot.file_offset));
                calls.borrow_mut().push((program, slot.index));
                links.push(RegisteredLink::MultiUProbe {
                    program, slots: vec![slot.index],
                    fds: vec![File::open("/dev/null")?.into()], registration: pairs.register(),
                });
                Ok(())
            }), |_| Some(55)).unwrap();
        assert_eq!(
            *calls.borrow(),
            [
                ("p11_return", 0),
                ("p11_return", 1),
                ("p11_entry", 0),
                ("p11_entry", 1)
            ]
        );
        let completions = std::cell::Cell::new(60);
        pairs.seal(
            &outcome.continuity_rounds,
            Some(AttachBaseline { loss: 7, fault: 0 }),
            Some(0),
            &links,
            &current_static_sides_from(&links),
            &retained,
            || {
                let now = completions.get();
                completions.set(now + 10);
                Some(now)
            },
        );
        let first = pairs
            .stamp_for(
                &slots[0],
                &pins,
                &links,
                &current_static_sides_from(&links),
                &retained,
            )
            .unwrap();
        assert_eq!((first.started_ns, first.completed_ns), (10, 60));
        assert!(
            first.started_ns < 30 && first.completed_ns > 30,
            "EXEC between return and entry cannot look like a completed earlier generation"
        );
        let second = pairs
            .stamp_for(
                &slots[1],
                &pins,
                &links,
                &current_static_sides_from(&links),
                &retained,
            )
            .unwrap();
        assert_eq!((second.started_ns, second.completed_ns), (20, 70));
        assert_eq!(
            outcome.completed,
            [(0, Some(55)), (1, Some(55))],
            "private stamps do not replace existing public completion samples"
        );
    }

    #[test]
    fn pid_continuity_multi_invalidates_connected_survivors_before_detach() {
        use pid_continuity::{AttachBaseline, AttachRound, PairBook};
        let (_dir, pins, target) = pid_continuity::tests::fixture();
        let targets: Vec<_> = (0..4)
            .map(|index| {
                let mut target = target.clone();
                target.slot.index = index;
                target.slot.file_offset += u64::from(index) * 8;
                target
            })
            .collect();
        let mut pairs = PairBook::default();
        let mut links = Vec::new();
        let mut retained = BTreeMap::new();
        let bundles = [
            ("p11_return", vec![0, 1]),
            ("p11_entry", vec![0]),
            ("p11_entry", vec![1, 2]),
            ("p11_return", vec![2]),
            ("p11_return", vec![3]),
            ("p11_entry", vec![3]),
        ]
        .into_iter()
        .map(|(program, slots)| MultiLinkBundle {
            program,
            slots,
            links: vec![File::open("/dev/null").unwrap().into()],
        })
        .collect();
        publish_kept_multi_bundles(&mut links, &mut retained, bundles, &targets, &mut pairs);
        pairs.seal(
            &[
                AttachRound {
                    slots: vec![0, 1, 2],
                    started_ns: Some(10),
                    last_call_ns: Some(20),
                },
                AttachRound {
                    slots: vec![3],
                    started_ns: Some(10),
                    last_call_ns: Some(20),
                },
            ],
            Some(AttachBaseline { loss: 0, fault: 0 }),
            Some(0),
            &links,
            &current_static_sides_from(&links),
            &retained,
            || Some(30),
        );
        let requested = BTreeSet::from([0]);
        let affected = plan_group_rebuild(&links, &requested).unwrap();
        assert_eq!(affected, BTreeSet::from([0, 1, 2]));
        pairs.invalidate(&affected);
        let detached = extract_selected_links(&mut links, &mut pairs, |link| {
            link.slots().iter().any(|slot| affected.contains(slot))
        });
        let failures = detach_selected_with(
            detached
                .into_iter()
                .map(|link| (link.producer(), link))
                .collect(),
            |link| {
                for target in targets.iter().take(3) {
                    assert!(pairs.recorded_generation(target.slot.index).is_none());
                    assert!(
                        pairs
                            .stamp_for(
                                &target.slot,
                                &pins,
                                &links,
                                &current_static_sides_from(&links),
                                &retained
                            )
                            .is_none(),
                        "all transitive survivors are invalid before the first native detach"
                    );
                }
                assert!(
                    pairs
                        .stamp_for(
                            &targets[3].slot,
                            &pins,
                            &links,
                            &current_static_sides_from(&links),
                            &retained
                        )
                        .is_some()
                );
                drop(link);
                Err(io::Error::other("scripted native detach failure").into())
            },
        );
        assert_eq!(failures.len(), 4);
        assert!(
            attachment_admission(
                &failures.iter().map(ToString::to_string).collect::<Vec<_>>(),
                true
            )
            .is_err()
        );
    }

    #[test]
    fn pid_continuity_replace_partial_cleanup_and_fallback_invalidate() {
        use pid_continuity::{AttachBaseline, AttachRound, NativeAttempt, PairBook};
        let (_dir, pins, target) = pid_continuity::tests::fixture();
        let mut sibling = target.clone();
        sibling.slot.index = 1;
        sibling.slot.file_offset += 8;
        let targets = [target.clone(), sibling.clone()];
        let slot = target.slot.clone();
        let mut pairs = PairBook::default();
        let mut links = pid_continuity::tests::pair(&mut pairs);
        let mut retained = BTreeMap::from([(0, target.clone())]);
        pairs.seal(
            &[AttachRound {
                slots: vec![0],
                started_ns: Some(10),
                last_call_ns: Some(20),
            }],
            Some(AttachBaseline { loss: 5, fault: 0 }),
            Some(0),
            &links,
            &current_static_sides_from(&links),
            &retained,
            || Some(30),
        );
        let old_generation = pairs.recorded_generation(0).unwrap();
        drop(extract_selected_links(&mut links, &mut pairs, |_| true));
        assert!(pairs.recorded_generation(0).is_none());
        prune_linkless_retained(&mut retained, &links);
        let attach_targets = targets
            .iter()
            .map(|target| (target.slot.index, (target.path.clone(), target.abi)))
            .collect();
        let groups = group_static_slots(
            &[slot.clone(), sibling.slot.clone()],
            CapturePolicy::AggregateOnly,
            false,
            &attach_targets,
        );
        let (bundles, outcome) = attach_target_groups_observed_with(
            &groups,
            |_| Some(55),
            |_, _, sites, is_return| {
                NativeAttempt::run(
                    || Some(40),
                    || {
                        if !is_return
                            && sites
                                .iter()
                                .any(|(offset, _)| *offset == sibling.slot.file_offset)
                        {
                            return Err(io::Error::from_raw_os_error(libc::EINVAL));
                        }
                        Ok(File::open("/dev/null")?.into())
                    },
                )
            },
        )
        .unwrap();
        publish_kept_multi_bundles(&mut links, &mut retained, bundles, &targets, &mut pairs);
        pairs.seal(
            &outcome.continuity_rounds,
            Some(AttachBaseline { loss: 5, fault: 1 }),
            Some(1),
            &links,
            &current_static_sides_from(&links),
            &retained,
            || Some(60),
        );
        assert!(pairs.recorded_generation(0).unwrap() > old_generation);
        assert!(
            pairs.recorded_generation(1).is_none(),
            "the failed replacement entry has no pair authority"
        );
        let affected = plan_group_rebuild(&links, &BTreeSet::from([1])).unwrap();
        assert_eq!(
            affected,
            BTreeSet::from([0, 1]),
            "partial replacement cleanup includes its successful sibling"
        );
        let survivor = retained[&0].clone();
        pairs.invalidate(&affected);
        drop(extract_selected_links(&mut links, &mut pairs, |link| {
            link.slots().iter().any(|slot| affected.contains(slot))
        }));
        assert!(pairs.recorded_generation(0).is_none());
        prune_linkless_retained(&mut retained, &links);
        let targets = BTreeMap::from([(0, (survivor.path.clone(), survivor.abi))]);
        let groups = group_static_slots(
            std::slice::from_ref(&slot),
            CapturePolicy::AggregateOnly,
            false,
            &targets,
        );
        let (bundles, outcome) = reattach_rebuilt_groups_observed_with(
            &groups,
            |_| Some(75),
            |_, _, _, _| NativeAttempt::run(|| Some(70), || Ok(File::open("/dev/null")?.into())),
            drop,
        );
        publish_kept_multi_bundles(&mut links, &mut retained, bundles, &[survivor], &mut pairs);
        pairs.seal(
            &outcome.continuity_rounds,
            Some(AttachBaseline { loss: 5, fault: 1 }),
            Some(1),
            &links,
            &current_static_sides_from(&links),
            &retained,
            || Some(80),
        );
        assert!(
            pairs
                .stamp_for(
                    &slot,
                    &pins,
                    &links,
                    &current_static_sides_from(&links),
                    &retained
                )
                .unwrap()
                .generation
                > old_generation
        );
        let domain = events::DiscoveryDomain::test_standin(801);
        let tap = PidLifecycleTap::test_for(7, domain.clone());
        tap.begin_read(Some(90));
        tap.observe_empty(Some(90), 0, 0);
        invalidate_pid_session(&mut pairs, Some(&tap)); // shared by producer detach and Drop, even with no links
        assert_eq!(tap.facts(), Err(PidContinuityRefusal::Terminal));
        assert!(pairs.recorded_generation(0).is_none());
        drop(extract_selected_links(&mut links, &mut pairs, |_| true));
        let fallback_domain = events::DiscoveryDomain::test_standin(801);
        assert!(!domain.same_allocation(&fallback_domain));
        let fallback_tap = PidLifecycleTap::test_for(7, fallback_domain.clone());
        assert!(!tap.matches_domain(&fallback_domain));
        assert_eq!(
            fallback_tap.facts().unwrap(),
            pid_continuity::LifecycleFacts::default()
        );
        let fallback = PairBook::default();
        assert!(
            fallback
                .stamp_for(
                    &slot,
                    &pins,
                    &links,
                    &current_static_sides_from(&links),
                    &retained
                )
                .is_none()
        );
    }

    #[test]
    fn pid_continuity_multi_publishes_only_final_kept_round_and_targets() {
        use pid_continuity::{AttachBaseline, NativeAttempt, PairBook};
        let (_dir, pins, target) = pid_continuity::tests::fixture();
        let (_later_dir, _later_pins, mut later) = pid_continuity::tests::fixture();
        later.slot.index = 3;
        let survivors: Vec<_> = (0..3)
            .map(|index| {
                let mut target = target.clone();
                target.slot.index = index;
                target.slot.file_offset += u64::from(index) * 8;
                target
            })
            .chain([later.clone()])
            .collect();
        let slots: Vec<_> = survivors.iter().map(|target| target.slot.clone()).collect();
        let targets = survivors
            .iter()
            .map(|target| (target.slot.index, (target.path.clone(), target.abi)))
            .collect();
        let mut groups = group_static_slots(&slots, CapturePolicy::AggregateOnly, false, &targets);
        groups.sort_by_key(|group| group.members[0].slot.index);
        let poison = slots[1].file_offset;
        for error in [libc::EMFILE, libc::ENOTSUP] {
            let times = std::cell::Cell::new(100);
            let (bundles, outcome) = reattach_rebuilt_groups_observed_with(
                &groups,
                |_| Some(190),
                |_, path, sites, is_return| {
                    NativeAttempt::run(
                        || {
                            let now = times.get();
                            times.set(now + 1);
                            Some(now)
                        },
                        || {
                            if path == later.path {
                                return Err(io::Error::from_raw_os_error(error));
                            }
                            if !is_return && sites.iter().any(|(offset, _)| *offset == poison) {
                                return Err(io::Error::from_raw_os_error(libc::EINVAL));
                            }
                            Ok(File::open("/dev/null")?.into())
                        },
                    )
                },
                drop,
            );
            assert_eq!(outcome.exhausted, error == libc::EMFILE);
            assert_eq!(outcome.completed, [(0, Some(190)), (2, Some(190))]);
            assert_eq!(outcome.continuity_rounds.len(), 1);
            let round = &outcome.continuity_rounds[0];
            assert_eq!(round.slots, [0, 2]);
            assert_eq!(
                (round.started_ns, round.last_call_ns),
                (Some(106), Some(107)),
                "the discarded wide round cannot lend its timing to final kept links"
            );
            let mut pairs = PairBook::default();
            let mut links = Vec::new();
            let mut retained = BTreeMap::new();
            publish_kept_multi_bundles(&mut links, &mut retained, bundles, &survivors, &mut pairs);
            assert_eq!(
                retained.keys().copied().collect::<Vec<_>>(),
                [0, 2],
                "the actual kept survivor registry publication must restore its exact target"
            );
            pairs.seal(
                &outcome.continuity_rounds,
                Some(AttachBaseline { loss: 7, fault: 0 }),
                Some(0),
                &links,
                &current_static_sides_from(&links),
                &retained,
                || Some(200),
            );
            let first = pairs
                .stamp_for(
                    &slots[0],
                    &pins,
                    &links,
                    &current_static_sides_from(&links),
                    &retained,
                )
                .unwrap();
            let generation = first.generation;
            assert_eq!((first.started_ns, first.completed_ns), (106, 200));
            assert_eq!(
                pairs
                    .stamp_for(
                        &slots[2],
                        &pins,
                        &links,
                        &current_static_sides_from(&links),
                        &retained
                    )
                    .unwrap()
                    .generation,
                generation
            );
            let second_survivor = retained[&2].clone();
            let affected = plan_group_rebuild(&links, &BTreeSet::from([0])).unwrap();
            assert_eq!(affected, BTreeSet::from([0, 2]));
            pairs.invalidate(&affected);
            drop(extract_selected_links(&mut links, &mut pairs, |link| {
                link.slots().iter().any(|slot| affected.contains(slot))
            }));
            prune_linkless_retained(&mut retained, &links);
            assert!(retained.is_empty());
            let targets =
                BTreeMap::from([(2, (second_survivor.path.clone(), second_survivor.abi))]);
            let rebuilt = group_static_slots(
                std::slice::from_ref(&second_survivor.slot),
                CapturePolicy::AggregateOnly,
                false,
                &targets,
            );
            let (bundles, outcome) = reattach_rebuilt_groups_observed_with(
                &rebuilt,
                |_| Some(209),
                |_, _, _, _| {
                    NativeAttempt::run(
                        || {
                            let now = times.get();
                            times.set(now + 1);
                            Some(now)
                        },
                        || Ok(File::open("/dev/null")?.into()),
                    )
                },
                drop,
            );
            publish_kept_multi_bundles(
                &mut links,
                &mut retained,
                bundles,
                &[second_survivor],
                &mut pairs,
            );
            pairs.seal(
                &outcome.continuity_rounds,
                Some(AttachBaseline { loss: 7, fault: 0 }),
                Some(0),
                &links,
                &current_static_sides_from(&links),
                &retained,
                || Some(210),
            );
            assert!(
                pairs
                    .stamp_for(
                        &slots[2],
                        &pins,
                        &links,
                        &current_static_sides_from(&links),
                        &retained
                    )
                    .unwrap()
                    .generation
                    > generation,
                "restored held facts remain usable for the next survivor rebuild"
            );
            assert!(!retained.contains_key(&0));
        }
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
                "OBJECT_DESCRIPTORS",
                "OBJECT_ZERO",
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
    /// quantum per call, stops at the shared allowance leaving the rest in
    /// the ring, and serves every staged item before anything newer.
    #[test]
    fn discovery_staging_keeps_ring_order_and_leaves_overflow_in_the_ring() {
        let mut ring: std::collections::VecDeque<_> = discovery_items(0, 10).into();
        ring.insert(3, events::DiscoveryItem::Malformed);
        let mut stage = DiscoveryStage::default();

        let outcome = stage.stage(4, DiscoveryStage::CAPACITY, || ring.pop_front());
        assert_eq!(outcome.staged, 4);
        assert!(!outcome.capacity_blocked);
        let outcome = stage.stage(100, DiscoveryStage::CAPACITY, || ring.pop_front());
        assert_eq!(outcome.staged, 7, "the ring ran dry");
        assert!(!outcome.capacity_blocked);
        let outcome = stage.stage(100, DiscoveryStage::CAPACITY, || ring.pop_front());
        assert_eq!(outcome.staged, 0);
        assert!(!outcome.capacity_blocked);
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
        let outcome = stage.stage(usize::MAX, DiscoveryStage::CAPACITY, || ring.pop_front());
        assert_eq!(outcome.staged, DiscoveryStage::CAPACITY);
        assert!(
            outcome.capacity_blocked,
            "the shared allowance stops the move, not the quantum"
        );
        assert_eq!(ring.len(), 5, "overflow waits in the ring, never dropped");
        let outcome = stage.stage(1, DiscoveryStage::CAPACITY, || ring.pop_front());
        assert_eq!(outcome.staged, 0, "a full FIFO stages nothing");
        assert!(outcome.capacity_blocked);
    }

    /// I2: the shared cap is enforced structurally by the FIFO, not by
    /// caller quanta. No quantum stages past `shared_cap`, however large,
    /// and the outcome says whether the allowance stopped the move.
    #[test]
    fn discovery_staging_enforces_the_shared_cap_structurally() {
        let mut ring: std::collections::VecDeque<_> = discovery_items(0, 100).into();
        let mut stage = DiscoveryStage::default();
        let outcome = stage.stage(usize::MAX, 10, || ring.pop_front());
        assert_eq!(outcome.staged, 10);
        assert!(outcome.capacity_blocked);
        assert_eq!(stage.len(), 10);
        assert_eq!(ring.len(), 90);
        // A zero share stages nothing and reports blocked, never empty.
        let outcome = stage.stage(usize::MAX, 0, || ring.pop_front());
        assert_eq!(outcome.staged, 0);
        assert!(outcome.capacity_blocked);
        assert_eq!(ring.len(), 90, "nothing was consumed from the ring");
        // Draining the FIFO frees the same share again.
        stage.pop();
        let outcome = stage.stage(usize::MAX, 10, || ring.pop_front());
        assert_eq!(outcome.staged, 1);
        assert!(outcome.capacity_blocked);
        assert_eq!(stage.len(), 10);
    }

    /// H5 storage: staging and readiness stop exactly at the shared
    /// allowance. One mode stages the full share in a single quantum;
    /// the twin repeats small quanta to the same boundary with malformed
    /// items interleaved. The readiness predicate polls DISCOVERY only
    /// while staged plus engine-held leaves room — a snapshot per call,
    /// so a stale decision never changes under the waiter — with exact
    /// boundary, overflow-safe arithmetic and honest null cases. The ring
    /// cursor advances exactly per staged item, never past the stop.
    #[test]
    fn discovery_shared_capacity_gates_staging_and_readiness() {
        // Mode one: a single quantum fills the whole share exactly.
        let mut ring: std::collections::VecDeque<_> =
            discovery_items(0, DiscoveryStage::CAPACITY as u64 + 904).into();
        let mut stage = DiscoveryStage::default();
        let outcome = stage.stage(usize::MAX, DiscoveryStage::CAPACITY, || ring.pop_front());
        assert_eq!(outcome.staged, DiscoveryStage::CAPACITY);
        assert!(outcome.capacity_blocked);
        assert_eq!(ring.len(), 904, "overflow waits in the ring, never dropped");
        assert_eq!(stage.len(), DiscoveryStage::CAPACITY);
        // The boundary is exact, not off by one in either direction.
        let mut stage = DiscoveryStage::default();
        let mut ring: std::collections::VecDeque<_> = discovery_items(0, 100).into();
        let outcome = stage.stage(usize::MAX, 4_095, || ring.pop_front());
        assert_eq!((outcome.staged, outcome.capacity_blocked), (100, false));
        let mut stage = DiscoveryStage::default();
        let mut ring: std::collections::VecDeque<_> = discovery_items(0, 5_000).into();
        let outcome = stage.stage(usize::MAX, 4_095, || ring.pop_front());
        assert_eq!((outcome.staged, outcome.capacity_blocked), (4_095, true));
        assert_eq!(ring.len(), 905);

        // Twin: repeated small quanta reach the same boundary, malformed
        // items holding credits like records, order preserved.
        let mut items = discovery_items(0, 4_000);
        for at in [10, 1_000, 2_000, 3_000, 3_999] {
            items.insert(at, events::DiscoveryItem::Malformed);
        }
        let mut ring: std::collections::VecDeque<_> = items.into();
        ring.extend(discovery_items(4_000, 1_000));
        let mut stage = DiscoveryStage::default();
        let mut calls = 0u32;
        let mut total = 0usize;
        for _ in 0..17 {
            let outcome = stage.stage(256, DiscoveryStage::CAPACITY, || ring.pop_front());
            calls += 1;
            total += outcome.staged;
            if outcome.staged < 256 {
                assert!(
                    outcome.capacity_blocked,
                    "only the allowance shortens a quantum"
                );
            } else {
                assert!(!outcome.capacity_blocked);
            }
        }
        assert_eq!((calls, total), (17, DiscoveryStage::CAPACITY));
        assert_eq!(ring.len(), 909, "5,005 scripted minus 4,096 staged");
        let rest = stage.take();
        assert_eq!(rest.len(), DiscoveryStage::CAPACITY);
        let mut scripted = discovery_items(0, 4_000);
        for at in [10, 1_000, 2_000, 3_000, 3_999] {
            scripted.insert(at, events::DiscoveryItem::Malformed);
        }
        scripted.extend(discovery_items(4_000, 1_000));
        assert_eq!(
            stamps(&rest),
            stamps(&scripted[..DiscoveryStage::CAPACITY]),
            "repeated quanta preserve ring order with malformed inline"
        );

        // The ring cursor advances exactly per staged item: no lookahead
        // past the stop, even against an endless ring.
        let mut reads = 0usize;
        let mut stage = DiscoveryStage::default();
        let outcome = stage.stage(usize::MAX, 10, || {
            reads += 1;
            Some(events::DiscoveryItem::Malformed)
        });
        assert_eq!((outcome.staged, outcome.capacity_blocked), (10, true));
        assert_eq!(reads, 10, "the stop reads nothing past the share");

        // Readiness polls DISCOVERY only while staged plus engine-held
        // leaves room: exact boundary, overflow-safe.
        for (staged, held, poll) in [
            (0usize, 0usize, true),
            (4_095, 0, true),
            (4_096, 0, false),
            (4_000, 95, true),
            (4_000, 96, false),
            (0, 4_095, true),
            (0, 4_096, false),
            (100, usize::MAX, false),
            (usize::MAX, 0, false),
            (usize::MAX, usize::MAX, false),
        ] {
            assert_eq!(
                DiscoveryStage::poll_discovery(staged, held),
                poll,
                "staged={staged} held={held}"
            );
        }

        // Stale readiness is a snapshot: decisions flip only on fresh
        // calls as staging fills and draining frees the share.
        let mut ring: std::collections::VecDeque<_> = discovery_items(0, 4_200).into();
        let mut stage = DiscoveryStage::default();
        assert!(DiscoveryStage::poll_discovery(stage.len(), 0));
        let outcome = stage.stage(usize::MAX, DiscoveryStage::CAPACITY, || ring.pop_front());
        assert_eq!(outcome.staged, DiscoveryStage::CAPACITY);
        let stale = DiscoveryStage::poll_discovery(stage.len(), 0);
        assert!(!stale, "a full share stops the poll");
        stage.pop();
        assert!(
            DiscoveryStage::poll_discovery(stage.len(), 0),
            "one freed credit reopens the poll"
        );
        assert!(!stale, "the earlier decision is unchanged");

        // Null cases: an empty ring stages nothing without blocking, and a
        // null quantum is the caller's choice, never a capacity stop.
        let mut ring: std::collections::VecDeque<events::DiscoveryItem> =
            std::collections::VecDeque::new();
        let mut stage = DiscoveryStage::default();
        let outcome = stage.stage(100, DiscoveryStage::CAPACITY, || ring.pop_front());
        assert_eq!((outcome.staged, outcome.capacity_blocked), (0, false));
        let mut ring: std::collections::VecDeque<_> = discovery_items(0, 10).into();
        let outcome = stage.stage(0, DiscoveryStage::CAPACITY, || ring.pop_front());
        assert_eq!((outcome.staged, outcome.capacity_blocked), (0, false));
        assert_eq!(ring.len(), 10, "a null quantum reads nothing");
        let mut stage = DiscoveryStage::default();
        let mut ring: std::collections::VecDeque<_> = discovery_items(0, 4_100).into();
        stage.stage(usize::MAX, DiscoveryStage::CAPACITY, || ring.pop_front());
        let outcome = stage.stage(0, DiscoveryStage::CAPACITY, || ring.pop_front());
        assert_eq!(
            (outcome.staged, outcome.capacity_blocked),
            (0, false),
            "a null quantum reports the caller's choice even when full"
        );

        // Both production seams use the shared helpers: staging subtracts
        // the engine hold for its share, readiness polls through the
        // predicate. (Real-sessions seams; the behavior above pins them.)
        let source = include_str!("attach.rs");
        assert!(
            source.contains("DiscoveryStage::CAPACITY.saturating_sub(engine_held)"),
            "staging sizes its share from the engine hold"
        );
        assert!(
            source.contains("DiscoveryStage::poll_discovery("),
            "readiness polls through the shared predicate"
        );
    }

    #[test]
    fn embedded_capture_adapter_symbol_match_is_exact() {
        let helper = "object_emit_get_attributes";
        for symbol in [
            "_RNvCscPIs3K62KxS_13p11scope_ebpf26object_emit_get_attributes",
            "_RNvCsburksC6UTXr_13p11scope_ebpf26object_emit_get_attributes",
            "_RNvC13p11scope_ebpf26object_emit_get_attributes",
        ] {
            assert!(super::embedded_adapter_symbol_matches(symbol, helper));
        }
        for symbol in [
            "_RNvXs1_NtNtNtCsoa9cz3JwRE_4core3ops8function5implsQNCNvCscPIs3K62KxS_13p11scope_ebpf26object_emit_get_attributes0INtB7_5FnMutTyEE8call_mutBR_",
            "_RNvCscPIs3K62KxS_13p11scope_ebpf26object_emit_get_attributes_suffix",
            "_RNvCscPIs3K62KxS_13p11scope_ebpf32prefixobject_emit_get_attributes",
            "_RNvCs_13p11scope_ebpf26object_emit_get_attributes",
            "_RNvCs!_13p11scope_ebpf26object_emit_get_attributes",
        ] {
            assert!(!super::embedded_adapter_symbol_matches(symbol, helper));
        }
        let misleading = "prefix13p11scope_ebpf26object_emit_get_attributes";
        assert!(!super::embedded_adapter_symbol_matches(
            &format!("_RNvCsa_13p11scope_ebpf{}{misleading}", misleading.len()),
            helper
        ));
    }

    #[test]
    fn embedded_object_capture_probe_refuses_missing_ambiguous_and_half_wired() {
        fn refused(parsed: aya_obj::Object, reason: &str) {
            let error =
                std::panic::catch_unwind(|| super::embedded_object_capture_is_stubbed(parsed))
                    .expect_err("mutated embedded object must be refused");
            let message = error
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| error.downcast_ref::<&str>().copied())
                .unwrap_or("");
            assert!(message.contains(reason), "wrong refusal: {message}");
        }
        let parsed = aya_obj::Object::parse(crate::EBPF_OBJECT).unwrap();
        let emit = *parsed
            .functions
            .iter()
            .find(|(_, function)| {
                super::embedded_adapter_symbol_matches(&function.name, "object_emit_get_attributes")
            })
            .unwrap()
            .0;
        let reader = *parsed
            .functions
            .iter()
            .find(|(_, function)| function.name == "p11_request_cell")
            .unwrap()
            .0;
        let mut missing = parsed.clone();
        missing.functions.remove(&emit);
        refused(missing, "no exact return adapter");
        let mut misleading = parsed.clone();
        misleading
            .functions
            .get_mut(&emit)
            .unwrap()
            .name
            .push_str("_suffix");
        refused(misleading, "no exact return adapter");
        let mut duplicate = parsed.clone();
        let address = duplicate
            .functions
            .keys()
            .map(|(_, address)| *address)
            .max()
            .unwrap()
            + 8;
        let mut clone = duplicate.functions[&emit].clone();
        clone.name = "_RNvCsa_13p11scope_ebpf26object_emit_get_attributes".into();
        duplicate.functions.insert((emit.0, address), clone);
        refused(duplicate, "several exact return adapters");
        let mut missing = parsed.clone();
        missing.functions.remove(&reader);
        refused(missing, "lacks request reader");
        let mut wrong_btf = parsed.clone();
        wrong_btf
            .functions
            .get_mut(&reader)
            .unwrap()
            .func_info
            .func_info[0]
            .type_id = 0;
        refused(wrong_btf, "original BTF FUNC");
        let mut half_wired = parsed;
        let body = &mut half_wired.functions.get_mut(&emit).unwrap().instructions;
        let instruction = *body.last().unwrap();
        body.resize(
            if cfg!(feature = "stub-object-attributes") {
                300
            } else {
                49
            },
            instruction,
        );
        refused(half_wired, "half-wired embedded object");
    }

    #[test]
    fn embedded_object_capture_entry_requires_real_calls() {
        let parsed = aya_obj::Object::parse(crate::EBPF_OBJECT).unwrap();
        let (entry, reader_id) = super::embedded_object_capture_entry(parsed);
        let captures = !cfg!(feature = "stub-object-attributes");
        assert_eq!(
            super::embedded_entry_reaches_reader(&entry, reader_id),
            captures
        );
        let mut unknown = entry.clone();
        let (at, instruction) = unknown
            .instructions
            .iter_mut()
            .enumerate()
            .find(|(_, instruction)| instruction.code == 0x85 && instruction.src_reg() == 1)
            .unwrap();
        instruction.imm = i32::try_from(entry.instructions.len() - at).unwrap();
        assert!(
            std::panic::catch_unwind(|| super::embedded_entry_reaches_reader(&unknown, reader_id))
                .is_err()
        );
        if captures {
            let target = entry
                .func_info
                .func_info
                .iter()
                .find(|info| info.type_id == reader_id)
                .expect("FULL entry must link the actual request reader")
                .insn_off as usize;
            let mut removed = entry;
            let mut changed = 0;
            for (at, instruction) in removed.instructions.iter_mut().enumerate() {
                if instruction.code == 0x85
                    && instruction.src_reg() == 1
                    && (at + 1).checked_add_signed(instruction.imm as isize) == Some(target)
                {
                    instruction.code = 0xb7;
                    instruction.set_src_reg(0);
                    instruction.imm = 0;
                    changed += 1;
                }
            }
            assert!(changed > 0, "actual reader call mutation must be nonzero");
            assert!(
                !super::embedded_entry_reaches_reader(&removed, reader_id),
                "retained reader body/BTF alone cannot prove capture"
            );
        }
    }

    /// Forced-refusal / no-spurious-degrade control: the status a session
    /// reports over its setup-checked flavor agrees with the embedded
    /// bytes' probed flavor, in every build. (The wiring pin beside this
    /// proves the method reads the stored flavor.) A stubbed build that
    /// claimed available — or a FULL build that claimed unavailable —
    /// fails here.
    #[test]
    fn session_object_capture_status_matches_bytes() {
        let checked = super::checked_embedded_flavor().expect("bytes agree with the build");
        let status = crate::render::ObjectCaptureEvidence::for_build(checked.stubbed);
        assert_eq!(status.available, !super::embedded_object_is_stubbed());
        if status.available {
            assert_eq!(status.reason, None);
        } else {
            assert_eq!(status.reason, Some("not_enabled"));
        }
    }

    /// P0-only ship vehicle: the embedded Detailed object carries
    /// stubbed attribute capture exactly when the `stub-object-attributes`
    /// feature built it. Both directions: a silent unwire fails featured
    /// builds, a silent stub fails default builds. The live load test
    /// proves the stubbed bytes load where FULL is refused.
    #[test]
    fn embedded_object_stub_matches_feature() {
        assert_eq!(
            super::embedded_object_is_stubbed(),
            cfg!(feature = "stub-object-attributes"),
            "embedded Detailed bytes must follow the stub feature"
        );
    }

    /// Production probe, positive control: the real embedded bytes report
    /// this build's flavor in every flavor (FULL default, P0, unsafe).
    #[test]
    fn production_probe_matches_embedded_bytes_in_this_build() {
        let flavor = super::embedded_flavor_from_bytes(crate::EBPF_OBJECT)
            .expect("embedded Detailed bytes must probe");
        assert_eq!(
            flavor.stubbed,
            cfg!(feature = "stub-object-attributes"),
            "probed stub flavor must match the build feature"
        );
        assert_eq!(
            flavor.unsafe_present,
            cfg!(feature = "unsafe-unvalidated-metadata"),
            "probed unsafe presence must match the build feature"
        );
    }

    /// Production stub rule agrees with the exact-symbol test probe on the
    /// real bytes, in every flavor.
    #[test]
    fn production_stub_probe_matches_test_probe_on_embedded_bytes() {
        let parsed = aya_obj::Object::parse(crate::EBPF_OBJECT).unwrap();
        assert_eq!(
            super::probed_capture_is_stubbed(parsed),
            Ok(super::embedded_object_is_stubbed())
        );
    }

    /// Production probe, negative byte control: garbage bytes are a probe
    /// error, never a flavor. Fails while the probe returns the feature.
    #[test]
    fn production_probe_rejects_garbage_bytes() {
        let error = super::embedded_flavor_from_bytes(b"not an ELF object")
            .expect_err("garbage bytes must not probe as any flavor");
        assert!(
            error.reason().contains("does not parse"),
            "{}",
            error.reason()
        );
    }

    /// Production stub core, negative controls: missing, ambiguous and
    /// half-wired evidence are errors, never a flavor and never a panic.
    /// Mirrors the test-probe refusal matrix; fails while the core
    /// returns the build feature.
    #[test]
    fn production_stub_core_refuses_missing_ambiguous_and_half_wired() {
        fn refused(parsed: aya_obj::Object, reason: &str) {
            let error = super::probed_capture_is_stubbed(parsed)
                .expect_err("mutated embedded object must be refused");
            assert!(
                error.reason().contains(reason),
                "wrong refusal: {}",
                error.reason()
            );
        }
        let parsed = aya_obj::Object::parse(crate::EBPF_OBJECT).unwrap();
        let emit = *parsed
            .functions
            .iter()
            .find(|(_, function)| {
                super::embedded_adapter_symbol_matches(&function.name, "object_emit_get_attributes")
            })
            .unwrap()
            .0;
        let reader = *parsed
            .functions
            .iter()
            .find(|(_, function)| function.name == "p11_request_cell")
            .unwrap()
            .0;
        let mut missing = parsed.clone();
        missing.functions.remove(&emit);
        refused(missing, "no exact return adapter");
        let mut misleading = parsed.clone();
        misleading
            .functions
            .get_mut(&emit)
            .unwrap()
            .name
            .push_str("_suffix");
        refused(misleading, "no exact return adapter");
        let mut duplicate = parsed.clone();
        let address = duplicate
            .functions
            .keys()
            .map(|(_, address)| *address)
            .max()
            .unwrap()
            + 8;
        let mut clone = duplicate.functions[&emit].clone();
        clone.name = "_RNvCsa_13p11scope_ebpf26object_emit_get_attributes".into();
        duplicate.functions.insert((emit.0, address), clone);
        refused(duplicate, "several exact return adapters");
        let mut missing = parsed.clone();
        missing.functions.remove(&reader);
        refused(missing, "lacks request reader");
        let mut wrong_btf = parsed.clone();
        wrong_btf
            .functions
            .get_mut(&reader)
            .unwrap()
            .func_info
            .func_info[0]
            .type_id = 0;
        refused(wrong_btf, "original BTF FUNC");
        let mut half_wired = parsed;
        let body = &mut half_wired.functions.get_mut(&emit).unwrap().instructions;
        let instruction = *body.last().unwrap();
        body.resize(
            if cfg!(feature = "stub-object-attributes") {
                300
            } else {
                49
            },
            instruction,
        );
        refused(half_wired, "half-wired embedded object");
    }

    /// Production unsafe probe, positive control: the real bytes report
    /// unsafe-decoder presence matching the build feature, in every flavor.
    #[test]
    fn production_unsafe_probe_matches_feature_in_this_build() {
        let parsed = aya_obj::Object::parse(crate::EBPF_OBJECT).unwrap();
        assert_eq!(
            super::probed_unsafe_is_present(&parsed),
            Ok(cfg!(feature = "unsafe-unvalidated-metadata"))
        );
    }

    /// Production unsafe probe reads the bytes, not the feature: planting
    /// every unsafe marker into default bytes reports present; stripping
    /// every marker from unsafe bytes reports absent. Fails while the
    /// probe returns the build feature.
    #[test]
    fn production_unsafe_probe_reads_bytes_not_feature() {
        let mut parsed = aya_obj::Object::parse(crate::EBPF_OBJECT).unwrap();
        if cfg!(feature = "unsafe-unvalidated-metadata") {
            for name in super::UNSAFE_PROGRAMS {
                assert!(
                    parsed.programs.remove(name).is_some(),
                    "unsafe bytes lack {name}"
                );
            }
            for (name, _) in super::FEATURE_POLICY_MAPS {
                assert!(
                    parsed.maps.remove(name).is_some(),
                    "unsafe bytes lack {name}"
                );
            }
            assert_eq!(super::probed_unsafe_is_present(&parsed), Ok(false));
        } else {
            let program = parsed
                .programs
                .values()
                .next()
                .expect("detailed bytes carry programs")
                .clone();
            for name in super::UNSAFE_PROGRAMS {
                assert!(
                    !parsed.programs.contains_key(name),
                    "default bytes carry {name}"
                );
                parsed.programs.insert(name.to_string(), program.clone());
            }
            let map = parsed
                .maps
                .values()
                .next()
                .expect("detailed bytes carry maps")
                .clone();
            for (name, _) in super::FEATURE_POLICY_MAPS {
                assert!(
                    !parsed.maps.contains_key(name),
                    "default bytes carry {name}"
                );
                parsed.maps.insert(name.to_string(), map.clone());
            }
            assert_eq!(super::probed_unsafe_is_present(&parsed), Ok(true));
        }
    }

    /// Production unsafe probe, half-wired control: a single planted
    /// marker in default bytes (or a single stripped marker in unsafe
    /// bytes) is an error, never a flavor.
    #[test]
    fn production_unsafe_probe_refuses_half_wired() {
        let mut parsed = aya_obj::Object::parse(crate::EBPF_OBJECT).unwrap();
        if cfg!(feature = "unsafe-unvalidated-metadata") {
            parsed.programs.remove(super::UNSAFE_PROGRAMS[0]);
        } else {
            let program = parsed
                .programs
                .values()
                .next()
                .expect("detailed bytes carry programs")
                .clone();
            parsed
                .programs
                .insert(super::UNSAFE_PROGRAMS[0].to_string(), program);
        }
        let error = super::probed_unsafe_is_present(&parsed)
            .expect_err("half-wired unsafe evidence must be refused");
        assert!(error.reason().contains("half-wired"), "{}", error.reason());
    }

    /// The flavor check accepts agreeing bytes in every flavor.
    #[test]
    fn flavor_check_accepts_agreeing_bytes() {
        let probed = super::EmbeddedFlavor {
            stubbed: cfg!(feature = "stub-object-attributes"),
            unsafe_present: cfg!(feature = "unsafe-unvalidated-metadata"),
        };
        assert_eq!(super::check_flavor_against_build(probed).unwrap(), probed);
    }

    /// A stubbed parse in a wired build (or the reverse) refuses with one
    /// plain message naming both values.
    #[test]
    fn flavor_check_refuses_stub_mismatch() {
        let probed = super::EmbeddedFlavor {
            stubbed: !cfg!(feature = "stub-object-attributes"),
            unsafe_present: cfg!(feature = "unsafe-unvalidated-metadata"),
        };
        let error = super::check_flavor_against_build(probed).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("stale or mismatched"), "{message}");
        assert!(message.contains("FULL"), "{message}");
        assert!(message.contains("P0"), "{message}");
    }

    /// An unsafe-presence disagreement refuses naming both values.
    #[test]
    fn flavor_check_refuses_unsafe_mismatch() {
        let probed = super::EmbeddedFlavor {
            stubbed: cfg!(feature = "stub-object-attributes"),
            unsafe_present: !cfg!(feature = "unsafe-unvalidated-metadata"),
        };
        let error = super::check_flavor_against_build(probed).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("stale or mismatched"), "{message}");
        assert!(message.contains("unsafe-unvalidated-metadata"), "{message}");
        if cfg!(feature = "unsafe-unvalidated-metadata") {
            assert!(message.contains("lack"), "{message}");
        } else {
            assert!(message.contains("contain"), "{message}");
        }
    }

    /// The checked flavor honors a planted mismatch with the refusal
    /// message, and agreeing bytes pass through.
    #[test]
    fn checked_flavor_honors_planted_mismatch() {
        let planted = super::EmbeddedFlavor {
            stubbed: !cfg!(feature = "stub-object-attributes"),
            unsafe_present: cfg!(feature = "unsafe-unvalidated-metadata"),
        };
        let _guard = super::hold_embedded_flavor_for_test(Ok(planted));
        let error = super::checked_embedded_flavor().unwrap_err();
        assert!(
            format!("{error:#}").contains("stale or mismatched"),
            "{error:#}"
        );
    }

    /// The test seam plants a flavor for the guard's lifetime and clears
    /// it on drop, so ordinary reads see real bytes again.
    #[test]
    fn flavor_override_holds_planted_value_until_drop() {
        let planted = super::EmbeddedFlavor {
            stubbed: true,
            unsafe_present: true,
        };
        {
            let _guard = super::hold_embedded_flavor_for_test(Ok(planted));
            assert_eq!(super::embedded_flavor().unwrap(), planted);
            assert_eq!(super::embedded_flavor().unwrap(), planted);
        }
        assert_eq!(
            super::embedded_flavor().unwrap().stubbed,
            super::embedded_flavor_from_bytes(crate::EBPF_OBJECT)
                .unwrap()
                .stubbed
        );
    }

    /// A planted stub mismatch refuses capture setup before any attach:
    /// `diagnostic` fails with the mismatch message without loading BPF,
    /// so this passes unprivileged. Fails while setup derives the flavor
    /// from the feature.
    #[test]
    fn mismatched_flavor_refuses_setup_before_attach() {
        let planted = super::EmbeddedFlavor {
            stubbed: !cfg!(feature = "stub-object-attributes"),
            unsafe_present: cfg!(feature = "unsafe-unvalidated-metadata"),
        };
        let _guard = super::hold_embedded_flavor_for_test(Ok(planted));
        let error = super::Session::diagnostic()
            .err()
            .expect("mismatched flavor must refuse setup");
        let message = format!("{error:#}");
        assert!(message.contains("stale or mismatched"), "{message}");
        assert!(message.contains("FULL"), "{message}");
        assert!(message.contains("P0"), "{message}");
    }

    /// Undeterminable bytes refuse setup the same way, with the probe
    /// reason attached. Fails while setup ignores the probe.
    #[test]
    fn undeterminable_flavor_refuses_setup_before_attach() {
        let _guard = super::hold_embedded_flavor_for_test(Err(super::FlavorProbeError::new(
            "no exact return adapter",
        )));
        let error = super::Session::diagnostic()
            .err()
            .expect("undeterminable flavor must refuse setup");
        let message = format!("{error:#}");
        assert!(
            message.contains("cannot determine embedded BPF object flavor"),
            "{message}"
        );
        assert!(message.contains("no exact return adapter"), "{message}");
    }

    /// Extract one top-level function body from this file's source for the
    /// wiring pins below (the uretprobe loader-contract shape).
    fn pin_body<'a>(
        source: &'a str,
        signature: &str,
        end: &str,
    ) -> std::result::Result<&'a str, String> {
        source
            .split_once(signature)
            .ok_or_else(|| format!("{signature} not found"))?
            .1
            .split_once(end)
            .map(|(body, _)| body)
            .ok_or_else(|| format!("{signature} body end not found"))
    }

    /// The planted-flavor seam is per thread: the holder's own thread reads
    /// the planted value while a sibling thread keeps reading the real
    /// bytes, so planting tests never leak a mismatch into tests running
    /// beside them. Fails while the hook is process-global.
    #[test]
    fn flavor_override_stays_on_the_planting_thread() {
        let bytes = super::embedded_flavor_from_bytes(crate::EBPF_OBJECT)
            .expect("embedded Detailed bytes must probe");
        let planted = super::EmbeddedFlavor {
            stubbed: !bytes.stubbed,
            unsafe_present: !bytes.unsafe_present,
        };
        let _guard = super::hold_embedded_flavor_for_test(Ok(planted));
        assert_eq!(
            super::embedded_flavor().expect("own thread reads the planted value"),
            planted
        );
        let seen = std::thread::spawn(|| super::embedded_flavor().expect("sibling reads bytes"))
            .join()
            .expect("sibling thread joins");
        assert_eq!(
            seen, bytes,
            "a sibling thread must see bytes, not the plant"
        );
    }

    /// The cache initializer is pinned to the object bytes: `embedded_flavor`
    /// must initialize from `embedded_flavor_from_bytes(crate::EBPF_OBJECT)`,
    /// and no step of the probe path may read the Cargo features. A normal
    /// test build cannot hold mismatched bytes, so the planted twins cannot
    /// tell a feature-reading initializer apart; this pin can. Non-vacuity:
    /// the feature-reading mutant fails below on the mutated source, and in
    /// the mutant build log with the test hook kept.
    #[test]
    fn embedded_flavor_cache_initializes_from_object_bytes() {
        fn contract(source: &str) -> std::result::Result<(), String> {
            let flavor = pin_body(source, "pub(crate) fn embedded_flavor()", "\n}\n")?;
            if !flavor.contains("embedded_flavor_from_bytes(crate::EBPF_OBJECT)") {
                return Err("embedded_flavor must initialize from the object bytes".to_string());
            }
            for signature in [
                "pub(crate) fn embedded_flavor()",
                "pub(crate) fn embedded_flavor_from_bytes(",
                "fn probed_capture_entry(",
                "fn probed_entry_reaches_reader(",
                "fn probed_capture_is_stubbed(",
                "fn probed_unsafe_is_present(",
            ] {
                let probed = pin_body(source, signature, "\n}\n")?;
                if probed.contains("cfg!(feature") {
                    return Err(format!("{signature} must probe bytes, not features"));
                }
            }
            Ok(())
        }

        let source = include_str!("attach.rs");
        contract(source).unwrap();
        let mutant = source.replacen(
            ".get_or_init(|| embedded_flavor_from_bytes(crate::EBPF_OBJECT))",
            ".get_or_init(|| Ok(super::EmbeddedFlavor { stubbed: cfg!(feature = \"stub-object-attributes\"), unsafe_present: cfg!(feature = \"unsafe-unvalidated-metadata\") }))",
            1,
        );
        assert_ne!(mutant, source, "the mutant changes the initializer");
        assert!(contract(&mutant).is_err());
    }

    /// Attach grouping and output evidence read the flavor the session was
    /// set up with, never a re-read of the global cache: the three grouping
    /// bodies pass the stored flavor and the evidence method reads it, with
    /// no silent fallback. Fails while any site re-reads the cache.
    #[test]
    fn session_flavor_feeds_grouping_and_evidence() {
        fn contract(source: &str) -> std::result::Result<(), String> {
            for signature in [
                "pub(crate) fn attach_targets(",
                "fn attach_targets_multi(",
                "fn rebuild_affected_groups(",
            ] {
                let grouped = pin_body(source, signature, "\n}\n")?;
                if !grouped.contains("self.embedded_flavor.unsafe_present") {
                    return Err(format!("{signature} must pass the session's flavor"));
                }
                if grouped.contains("probed_unsafe_for_grouping")
                    || grouped.contains("embedded_flavor()")
                {
                    return Err(format!("{signature} must not re-read the global cache"));
                }
            }
            let evidence = pin_body(source, "pub(crate) fn object_capture_evidence(", "\n}\n")?;
            if !evidence.contains("self.embedded_flavor.stubbed") {
                return Err("output evidence must read the session's flavor".to_string());
            }
            if evidence.contains("embedded_flavor()") || evidence.contains("unwrap_or") {
                return Err("output evidence must have no silent fallback".to_string());
            }
            Ok(())
        }

        let source = include_str!("attach.rs");
        contract(source).unwrap();
        let mutant = source.replacen(
            "self.embedded_flavor.unsafe_present",
            "probed_unsafe_for_grouping()",
            1,
        );
        assert_ne!(mutant, source, "the mutant reverts one grouping site");
        assert!(contract(&mutant).is_err());
    }

    /// The entry lookup refuses a detached entry key instead of panicking:
    /// the program's key need not be in the function map. Fails (panics at
    /// the index) while the lookup indexes the map.
    #[test]
    fn probed_entry_lookup_refuses_a_detached_entry_key() {
        let mut parsed = aya_obj::Object::parse(crate::EBPF_OBJECT).unwrap();
        let key = parsed
            .programs
            .get("p11_entry")
            .expect("embedded Detailed object lacks entry")
            .function_key();
        let entry = parsed
            .functions
            .remove(&key)
            .expect("embedded entry function present");
        let address = parsed
            .functions
            .keys()
            .map(|(_, address)| *address)
            .max()
            .unwrap()
            + 8;
        parsed.functions.insert((key.0, address), entry);
        let error = super::probed_capture_entry(parsed)
            .expect_err("a detached entry key must refuse, not panic");
        assert!(
            error.reason().contains("ambiguous embedded entry function"),
            "{}",
            error.reason()
        );
    }

    /// The stub rule has one copy: the exact-symbol test helpers delegate to
    /// the production probe, so the two cannot drift. (The agreement test
    /// beside them keeps pinning the wiring.) Fails while the helpers carry
    /// their own duplicated rule.
    #[test]
    fn stub_rule_tests_use_the_production_probe() {
        fn contract(source: &str) -> std::result::Result<(), String> {
            for (helper, production) in [
                ("fn embedded_object_capture_entry(", "probed_capture_entry("),
                (
                    "fn embedded_entry_reaches_reader(",
                    "probed_entry_reaches_reader(",
                ),
                (
                    "fn embedded_object_capture_is_stubbed(",
                    "probed_capture_is_stubbed(",
                ),
            ] {
                let delegated = pin_body(source, helper, "\n}\n")?;
                if !(delegated.contains(production) && delegated.contains(".expect(")) {
                    return Err(format!("{helper} must delegate to {production}"));
                }
            }
            Ok(())
        }

        let source = include_str!("attach.rs");
        contract(source).unwrap();
        let mutant = source.replacen(
            "probed_capture_is_stubbed(parsed)",
            "duplicated_stub_logic(parsed)",
            1,
        );
        assert_ne!(mutant, source, "the mutant reverts one helper");
        assert!(contract(&mutant).is_err());
    }

    /// Every flavor-mismatch refusal names the operator's fix: a clean
    /// rebuild. Both `check_flavor_against_build` directions and the
    /// undeterminable wrap carry the hint. Fails while the suffix names no fix.
    #[test]
    fn flavor_mismatch_names_a_rebuild() {
        for probed in [
            super::EmbeddedFlavor {
                stubbed: !cfg!(feature = "stub-object-attributes"),
                unsafe_present: cfg!(feature = "unsafe-unvalidated-metadata"),
            },
            super::EmbeddedFlavor {
                stubbed: cfg!(feature = "stub-object-attributes"),
                unsafe_present: !cfg!(feature = "unsafe-unvalidated-metadata"),
            },
        ] {
            let error = super::check_flavor_against_build(probed).unwrap_err();
            let message = format!("{error:#}");
            assert!(message.contains("stale or mismatched"), "{message}");
            assert!(
                message.contains("rebuild p11scope from a clean target directory"),
                "{message}"
            );
        }
        let _guard = super::hold_embedded_flavor_for_test(Err(super::FlavorProbeError::new(
            "test probe reason",
        )));
        let error = super::checked_embedded_flavor().unwrap_err();
        let message = format!("{error:#}");
        assert!(
            message.contains("cannot determine embedded BPF object flavor"),
            "{message}"
        );
        assert!(
            message.contains("rebuild p11scope from a clean target directory"),
            "{message}"
        );
    }

    /// The half-wired stub refusal is plain operator text, not reader/emit
    /// jargon. (The rebuild hint rides the shared mismatch suffix pinned
    /// beside this.) Fails while the reason names internals.
    #[test]
    fn half_wired_stub_refusal_is_plain_operator_text() {
        let parsed = aya_obj::Object::parse(crate::EBPF_OBJECT).unwrap();
        let emit = *parsed
            .functions
            .iter()
            .find(|(_, function)| {
                super::embedded_adapter_symbol_matches(&function.name, "object_emit_get_attributes")
            })
            .unwrap()
            .0;
        let mut half_wired = parsed;
        let body = &mut half_wired.functions.get_mut(&emit).unwrap().instructions;
        let instruction = *body.last().unwrap();
        body.resize(
            if cfg!(feature = "stub-object-attributes") {
                300
            } else {
                49
            },
            instruction,
        );
        let error =
            super::probed_capture_is_stubbed(half_wired).expect_err("half-wired must refuse");
        let reason = error.reason();
        assert!(reason.contains("half-wired"), "{reason}");
        assert!(!reason.contains("entry reader"), "{reason}");
        assert!(!reason.contains("emit "), "{reason}");
    }

    /// Load-refusal detector matrix: only the E2BIG budget errno
    /// classifies; every other errno — and a missing errno — stays a
    /// loud unrelated failure.
    #[test]
    fn verifier_budget_errno_matrix() {
        assert!(super::is_verifier_budget_errno(Some(libc::E2BIG)));
        for errno in [
            libc::EINVAL,
            libc::EACCES,
            libc::EPERM,
            libc::ENOMEM,
            libc::EFAULT,
        ] {
            assert!(
                !super::is_verifier_budget_errno(Some(errno)),
                "errno {errno} must not classify as a budget refusal"
            );
        }
        assert!(!super::is_verifier_budget_errno(None));
    }

    /// Load-refusal detector on real error values, both directions: a
    /// LoadError with E2BIG classifies; LoadErrors with other errnos —
    /// and non-load errors — never do, whatever the verifier log says.
    #[test]
    fn verifier_budget_refusal_real_errors() {
        fn load_error(errno: i32) -> aya::programs::ProgramError {
            aya::programs::ProgramError::LoadError {
                io_error: std::io::Error::from_raw_os_error(errno),
                verifier_log: aya_obj::VerifierLog::new("verifier spew".to_string()),
            }
        }
        assert!(super::is_verifier_budget_refusal(&load_error(libc::E2BIG)));
        for errno in [libc::EINVAL, libc::EACCES, libc::EPERM] {
            assert!(
                !super::is_verifier_budget_refusal(&load_error(errno)),
                "errno {errno} must not classify as a budget refusal"
            );
        }
        assert!(!super::is_verifier_budget_refusal(
            &aya::programs::ProgramError::NotLoaded
        ));
    }

    /// Load-refusal detector, live: a FULL root load either succeeds
    /// (bigger-limit kernels) or fails with a classified refusal. The
    /// classifier must agree with the real errno in both directions — a
    /// misfire fails. Default builds only; featured builds pin the
    /// stubbed load in `stubbed_roots_load`.
    #[cfg(not(feature = "stub-object-attributes"))]
    #[ignore = "root-owned BPF lane; FULL root load refusal is classified"]
    #[test]
    fn full_root_load_refusal_is_classified() {
        let btf = aya::Btf::from_sys_fs().expect("vmlinux BTF for typed task storage");
        let mut ebpf = super::load_capture_object(
            &btf,
            crate::run::resolve_ring_bytes(None),
            p11scope_ebpf_common::DISCOVERY_BYTES,
        )
        .expect("FULL object parses and creates maps");
        let program: &mut aya::programs::UProbe = ebpf
            .program_mut("p11_entry")
            .unwrap_or_else(|| panic!("FULL object missing p11_entry"))
            .try_into()
            .unwrap_or_else(|error| panic!("p11_entry is not an uprobe: {error}"));
        match program.load() {
            Ok(()) => println!("FULL p11_entry loads on this kernel"),
            Err(error) => {
                if let aya::programs::ProgramError::LoadError { io_error, .. } = &error {
                    let errno = io_error
                        .raw_os_error()
                        .expect("a real LoadError carries the BPF_PROG_LOAD errno");
                    assert_eq!(
                        super::is_verifier_budget_refusal(&error),
                        errno == libc::E2BIG,
                        "classifier must agree with errno {errno} in both directions"
                    );
                    println!("FULL p11_entry refused: errno={errno}");
                } else {
                    assert!(
                        !super::is_verifier_budget_refusal(&error),
                        "non-load errors never classify: {error}"
                    );
                }
            }
        }
    }

    /// P0-only ship vehicle, live: stub-featured bytes load both object
    /// roots on 1M-budget kernels, where FULL is refused with E2BIG.
    /// Featured builds only; the default-build refusal control is
    /// `full_root_load_refusal_is_classified`.
    #[cfg(feature = "stub-object-attributes")]
    #[ignore = "root-owned BPF lane; stubbed p11_entry/p11_return load on 1M kernels"]
    #[test]
    fn stubbed_roots_load() {
        let btf = aya::Btf::from_sys_fs().expect("vmlinux BTF for typed task storage");
        let mut ebpf = super::load_capture_object(
            &btf,
            crate::run::resolve_ring_bytes(None),
            p11scope_ebpf_common::DISCOVERY_BYTES,
        )
        .expect("stubbed object parses and creates maps");
        for root in ["p11_entry", "p11_return"] {
            let program: &mut aya::programs::UProbe = ebpf
                .program_mut(root)
                .unwrap_or_else(|| panic!("stubbed object missing {root}"))
                .try_into()
                .unwrap_or_else(|error| panic!("{root} is not an uprobe: {error}"));
            program
                .load()
                .unwrap_or_else(|error| panic!("stubbed {root} must load: {error}"));
        }
    }

    /// Owned provider + driver build for the real-Session retirement cells.
    /// The child prints READY, then idles waiting for 'G' (60 s bound) while
    /// the Session drives STOP/Q/retirement; nothing ever calls into it.
    struct CollectedSessionCell {
        _directory: tempfile::TempDir,
        provider: std::path::PathBuf,
        child: std::process::Child,
        output: std::io::BufReader<std::process::ChildStdout>,
    }

    impl Drop for CollectedSessionCell {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl CollectedSessionCell {
        fn build() -> anyhow::Result<Self> {
            use anyhow::Context as _;
            let directory = tempfile::tempdir()?;
            let source = directory.path().join("retirement-cell.c");
            std::fs::write(
                &source,
                include_str!("../tests/fixtures/detailed-thread-exit.c"),
            )?;
            let provider = directory.path().join("provider.so");
            let driver = directory.path().join("driver");
            for is_provider in [true, false] {
                let mut compiler = std::process::Command::new("cc");
                compiler.args([
                    "-std=c11",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-fno-builtin",
                    "-fno-stack-protector",
                    "-fno-omit-frame-pointer",
                ]);
                if is_provider {
                    compiler.args(["-fPIC", "-shared", "-DDETAILED_THREAD_EXIT_PROVIDER"]);
                } else {
                    compiler.arg("-ldl");
                }
                let output = compiler
                    .arg(&source)
                    .arg("-o")
                    .arg(if is_provider { &provider } else { &driver })
                    .output()?;
                anyhow::ensure!(
                    output.status.success(),
                    "owned fixture compilation failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            let mut child = std::process::Command::new(&driver)
                .arg(&provider)
                .arg(std::process::id().to_string())
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()?;
            let stdout = child.stdout.take().context("fixture output pipe")?;
            let mut cell = Self {
                _directory: directory,
                provider,
                child,
                output: std::io::BufReader::new(stdout),
            };
            cell.expect_ready()?;
            Ok(cell)
        }

        fn expect_ready(&mut self) -> anyhow::Result<()> {
            use std::io::BufRead as _;
            let mut line = String::new();
            self.output.read_line(&mut line)?;
            let fields: Vec<&str> = line.split_whitespace().collect();
            anyhow::ensure!(
                fields.len() == 6 && fields[0] == "READY",
                "owned driver READY line: {line:?}"
            );
            let numbers: Vec<u64> = fields[1..5]
                .iter()
                .map(|field| field.parse())
                .collect::<Result<_, _>>()?;
            let metadata = std::fs::metadata(&self.provider)?;
            use std::os::unix::fs::MetadataExt as _;
            anyhow::ensure!(
                numbers
                    == [
                        u64::from(self.child.id()),
                        u64::from(self.child.id()),
                        metadata.dev(),
                        metadata.ino()
                    ],
                "READY names this child and provider file: {numbers:?}"
            );
            Ok(())
        }

        /// Pin the owned provider in the child and plan COUNT_ONLY endpoints
        /// at the given file offsets into the provider.
        fn pin_and_plan(
            &self,
            offsets: &[u64],
        ) -> anyhow::Result<(super::PinnedObjects, super::AttachPlan)> {
            use anyhow::Context as _;
            use p11scope_manifest::identity::{mapping_file_key, open_object};
            let view = crate::process::ProcessView::open(
                crate::process::ProcessViewId(0),
                self.child.id(),
            )
            .map_err(anyhow::Error::msg)?;
            let file = open_object(&self.provider).map_err(anyhow::Error::msg)?;
            let mapping = mapping_file_key(&file).map_err(anyhow::Error::msg)?;
            let elf =
                p11scope_manifest::elf::ElfSnapshot::read(&file).map_err(anyhow::Error::msg)?;
            anyhow::ensure!(elf.abi() == super::ElfAbi::Lp64);
            let key = p11scope_manifest::maps::ObjectKey {
                device: p11scope_manifest::maps::Device {
                    major: mapping.device_major,
                    minor: mapping.device_minor,
                },
                inode: mapping.inode,
            };
            let module = crate::discovery::scan::ScannedModule {
                mapped_identity: None,
                double_loaded: false,
                view: view.id(),
                mount_namespace: view.mount_namespace(),
                key,
                path: self.provider.display().to_string(),
                decoder_abi: None,
                exports: vec![],
                tables: vec![],
                interfaces: vec![],
            };
            let (pins, skipped) = crate::discovery::identity::pin_scanned_view_objects(
                &view,
                &[module],
                &mut crate::discovery::scan::CaptureWorkBudget::default(),
            )
            .map_err(anyhow::Error::msg)?;
            anyhow::ensure!(
                skipped.is_empty(),
                "owned physical pin refused: {skipped:?}"
            );
            let pinned = pins.pinned().next().context("owned provider pin")?;
            anyhow::ensure!(pinned.key == key);
            let mut slots = Vec::new();
            for (index, offset) in offsets.iter().enumerate() {
                let index = u32::try_from(index)?;
                anyhow::ensure!(elf.is_executable_offset(*offset));
                slots.push(super::Slot {
                    index,
                    descriptor_index: index,
                    object: pinned.id,
                    object_path: self.provider.display().to_string(),
                    file_offset: *offset,
                    names: vec!["C_Initialize".into()],
                    aliased: false,
                    semantics: super::SlotSemantics::COUNT_ONLY,
                    semantic_authorized: false,
                    semantic_ambiguous: false,
                    fork_safe: false,
                    module_ids: vec![],
                });
            }
            let plan = super::AttachPlan::from_slots(slots);
            Ok((pins, plan))
        }

        fn provider_init_offset(&self) -> anyhow::Result<u64> {
            use anyhow::Context as _;
            use p11scope_manifest::identity::open_object;
            let file = open_object(&self.provider).map_err(anyhow::Error::msg)?;
            let elf =
                p11scope_manifest::elf::ElfSnapshot::read(&file).map_err(anyhow::Error::msg)?;
            let symbol = elf
                .defined_symbol("C_Initialize")
                .map_err(anyhow::Error::msg)?
                .context("owned provider function")?;
            Ok(symbol.file_offset)
        }
    }

    /// Drive STOP, quiescence and a real STOP/count0 Q on a real Session.
    fn collected_cell_stop_to_q(
        session: &mut super::Session,
    ) -> anyhow::Result<super::CollectedFinishQ> {
        use anyhow::Context as _;
        session.stop_gate().request_stop();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !session.stop_gate().quiescent() {
            anyhow::ensure!(
                std::time::Instant::now() < deadline,
                "real STOP never reached quiescence"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let producers = session
            .drain_producers()
            .context("real Session retains its producers")?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(q) = session.observe_collected_finish_q(&producers, None)? {
                return Ok(q);
            }
            anyhow::ensure!(
                std::time::Instant::now() < deadline,
                "real STOP/count0 never minted Q"
            );
            std::thread::yield_now();
        }
    }

    fn collected_cell_pool() -> crate::semantics_edge::resources::SemanticResourcePool {
        crate::semantics_edge::resources::SemanticResourcePool::reference_limit(
            crate::semantics_edge::resources::SEMANTIC_TRANSITION_SCRATCH + 2 * 1024 * 1024,
        )
    }

    fn collected_cell_input(
        slots: Vec<super::Slot>,
        storage: crate::semantics_edge::resources::ResourceLease,
    ) -> super::RetainedRetirementInput {
        match super::RetainedRetirementInput::from_reserved_removed(slots, storage) {
            Ok(input) => input,
            Err(_) => panic!("a fresh process-local input identity must be available"),
        }
    }

    /// Prepare/begin/poll through the Session carrier to its exact verdict.
    fn collected_cell_drive_to_closed(
        session: &mut super::Session,
        q: &super::CollectedFinishQ,
        removed: Vec<super::Slot>,
        reserve: &crate::semantics_edge::resources::SemanticResourceReserver,
    ) -> anyhow::Result<super::RetainedRetirementInput> {
        let mut input = Some(collected_cell_input(
            removed,
            reserve
                .reserve(64 * 1024)
                .expect("test pool pays the small removal input"),
        ));
        let ticket = loop {
            let progress =
                session.prepare_collected_static_retirement(q, &mut input, reserve, 1)?;
            anyhow::ensure!(progress.used == 1);
            match progress.state {
                super::CollectedRetirementState::Preparing => {}
                super::CollectedRetirementState::Prepared(ticket) => break ticket,
                _ => anyhow::bail!("real preparation did not seal its input"),
            }
        };
        loop {
            let progress = session.begin_collected_static_retirement(q, &ticket, 1)?;
            anyhow::ensure!(progress.used == 1);
            match progress.state {
                super::CollectedRetirementState::Transferring => {}
                super::CollectedRetirementState::Pending => break,
                _ => anyhow::bail!("real transfer did not reach its worker"),
            }
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            anyhow::ensure!(
                std::time::Instant::now() < deadline,
                "real batch close did not settle"
            );
            let progress = session.poll_collected_static_retirement(q, &ticket, 1)?;
            anyhow::ensure!(progress.used == 1);
            match progress.state {
                super::CollectedRetirementState::Pending => std::thread::yield_now(),
                super::CollectedRetirementState::Closed(input) => return Ok(input),
                _ => anyhow::bail!("real batch did not close exactly"),
            }
        }
    }

    fn collected_cell_endpoint_links(session: &super::Session, slot: u32) -> usize {
        session
            .links
            .iter()
            .filter(|link| link.slots().contains(&slot))
            .count()
    }

    fn collected_cell_released(session: &super::Session) -> usize {
        session
            .cleanup_worker
            .as_ref()
            .expect("the prestarted worker stays until terminal detach")
            .progress()
            .released
    }

    #[ignore = "privileged: real Detailed Session native retirement"]
    #[test]
    fn collected_retirement_stopped_session_q_closes_original_lp64() -> anyhow::Result<()> {
        let cell = CollectedSessionCell::build()?;
        let init = cell.provider_init_offset()?;
        let (pins, plan) = cell.pin_and_plan(&[init])?;
        let mut session = super::Session::start(
            &plan,
            &super::Scope::Pid(cell.child.id()),
            &pins,
            super::CapturePolicy::Allowlisted,
            None,
            None,
            None,
            super::BackendSelection::Multi,
        )?;
        anyhow::ensure!(
            session.attach_failures().is_empty(),
            "attach failures: {:?}",
            session.attach_failures()
        );
        anyhow::ensure!(session.backend_fallback().is_none());
        anyhow::ensure!(session.has_slot_link(0));
        let q = collected_cell_stop_to_q(&mut session)?;
        anyhow::ensure!(session.mutation_stopped());
        anyhow::ensure!(session.collected_retirement_is_physical());
        let endpoint_links = collected_cell_endpoint_links(&session, 0);
        anyhow::ensure!(
            endpoint_links == 2,
            "entry and return links: {endpoint_links}"
        );
        anyhow::ensure!(collected_cell_released(&session) == 0);
        let closed = collected_cell_drive_to_closed(
            &mut session,
            &q,
            plan.slots.clone(),
            &collected_cell_pool().reserver(),
        )?;
        let (removed, _storage) = closed.into_removed();
        anyhow::ensure!(removed.len() == 1 && removed[0].index == 0);
        anyhow::ensure!(!session.has_slot_link(0), "the closed link is gone");
        anyhow::ensure!(
            collected_cell_released(&session) == endpoint_links,
            "released equals the removed link count"
        );
        eprintln!("retirement-cell multi: closed slot 0, released {endpoint_links}");
        session.detach_producers_driven(|| false, &mut Vec::new())?;
        anyhow::ensure!(session.producers_detached);
        session.mint_native_completion()?;
        eprintln!("retirement-cell multi: terminal detach minted");
        Ok(())
    }

    #[ignore = "privileged: real Detailed Session native retirement"]
    #[test]
    fn collected_retirement_singles_session_defers_close_to_terminal_detach_lp64()
    -> anyhow::Result<()> {
        let cell = CollectedSessionCell::build()?;
        let init = cell.provider_init_offset()?;
        let (pins, plan) = cell.pin_and_plan(&[init])?;
        let mut session = super::Session::start(
            &plan,
            &super::Scope::Pid(cell.child.id()),
            &pins,
            super::CapturePolicy::Allowlisted,
            None,
            None,
            None,
            super::BackendSelection::Singles,
        )?;
        anyhow::ensure!(
            session.attach_failures().is_empty(),
            "attach failures: {:?}",
            session.attach_failures()
        );
        anyhow::ensure!(session.has_slot_link(0));
        let _q = collected_cell_stop_to_q(&mut session)?;
        anyhow::ensure!(session.mutation_stopped());
        anyhow::ensure!(!session.collected_retirement_is_physical());
        // No native retirement runs at Q on Singles: the removed link stays
        // in Session.links until the joined terminal detach closes it.
        anyhow::ensure!(session.has_slot_link(0));
        anyhow::ensure!(collected_cell_released(&session) == 0);
        eprintln!("retirement-cell singles: link stays past Q");
        session.detach_producers_driven(|| false, &mut Vec::new())?;
        anyhow::ensure!(session.producers_detached);
        anyhow::ensure!(!session.has_slot_link(0));
        session.mint_native_completion()?;
        eprintln!("retirement-cell singles: terminal detach closed it and minted");
        Ok(())
    }

    #[ignore = "privileged: real Detailed Session native retirement"]
    #[test]
    fn collected_partial_group_real_session_guards_refuse_until_terminal_lp64() -> anyhow::Result<()>
    {
        let cell = CollectedSessionCell::build()?;
        let init = cell.provider_init_offset()?;
        // Two endpoints, one provider file: one shared Multi group.
        let (pins, plan) = cell.pin_and_plan(&[init, init + 1])?;
        let mut session = super::Session::start(
            &plan,
            &super::Scope::Pid(cell.child.id()),
            &pins,
            super::CapturePolicy::Allowlisted,
            None,
            None,
            None,
            super::BackendSelection::Multi,
        )?;
        anyhow::ensure!(
            session.attach_failures().is_empty(),
            "attach failures: {:?}",
            session.attach_failures()
        );
        anyhow::ensure!(session.backend_fallback().is_none());
        // The group is really shared: every link covering slot 0 also covers
        // slot 1, on both the entry and the return side.
        let covering: Vec<&super::RegisteredLink> = session
            .links
            .iter()
            .filter(|link| link.slots().contains(&0))
            .collect();
        anyhow::ensure!(covering.len() == 2, "entry and return links");
        for link in &covering {
            anyhow::ensure!(
                link.slots() == [0, 1],
                "the group is shared: {:?}",
                link.slots()
            );
        }
        let programs: std::collections::BTreeSet<&str> = covering
            .iter()
            .filter_map(|link| match link {
                super::RegisteredLink::MultiUProbe { program, .. } => Some(*program),
                _ => None,
            })
            .collect();
        anyhow::ensure!(programs.len() == 2, "two Multi sides: {programs:?}");
        let q = collected_cell_stop_to_q(&mut session)?;
        anyhow::ensure!(session.collected_retirement_is_physical());
        // Remove slot 0 only: a strict partial-group subset at Q.
        let pool = collected_cell_pool();
        let reserve = pool.reserver();
        let mut input = Some(collected_cell_input(
            vec![plan.slots[0].clone()],
            reserve
                .reserve(64 * 1024)
                .expect("test pool pays the small removal input"),
        ));
        let split = loop {
            match session.defer_collected_partial_groups(&q, &mut input, &reserve, 1)? {
                super::DeferralProgress::Yielded | super::DeferralProgress::Scanning => {}
                super::DeferralProgress::Split { whole, deferred } => break (whole, deferred),
                super::DeferralProgress::NoPartial(_) => {
                    anyhow::bail!("a strict subset must defer, not pass through")
                }
            }
        };
        anyhow::ensure!(!split.1.registrations().is_empty());
        anyhow::ensure!(
            session.deferred_group_slots == std::collections::BTreeSet::from([0]),
            "slot 0 is deferred: {:?}",
            session.deferred_group_slots
        );
        anyhow::ensure!(session.has_slot_link(0) && session.has_slot_link(1));
        // Selective mutation refuses while the slot is deferred.
        let detach_error = session
            .detach_slots_with_ended(&[plan.slots[1].clone()], None, false)
            .unwrap_err();
        anyhow::ensure!(
            detach_error
                .to_string()
                .contains("collected group deferral"),
            "detach names the deferral: {detach_error:?}"
        );
        let attach_error = session
            .attach_targets(&[plan.slots[1].clone()], &pins)
            .unwrap_err();
        eprintln!("retirement-cell partial: attach refuses while deferred: {attach_error:?}");
        drop(split);
        // The terminal owned detach closes both members and mints: the mint
        // proves the deferred slot was terminally submitted.
        session.detach_producers_driven(|| false, &mut Vec::new())?;
        anyhow::ensure!(session.producers_detached);
        anyhow::ensure!(
            session.submitted_terminal_slots.contains(&0),
            "the deferred slot was terminally submitted: {:?}",
            session.submitted_terminal_slots
        );
        anyhow::ensure!(!session.has_slot_link(0) && !session.has_slot_link(1));
        session.mint_native_completion()?;
        eprintln!("retirement-cell partial: terminal detach closed both and minted");
        Ok(())
    }
}
