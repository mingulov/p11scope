//! Loading and attaching. One selected entry uprobe + one uretprobe serve
//! each slot; the attach cookie carries the slot index.

use crate::discovery::hooks::HookAbi;
use crate::discovery::identity::{PinnedObjectId, PinnedObjects};
use crate::discovery::loader::LoaderContextId;
use crate::events;
use crate::plan::{AttachPlan, Slot};
use crate::run::OwnedChild;
use anyhow::{Context as _, Result, anyhow, bail};
use aya::Ebpf;
use aya::maps::{Array, HashMap, Map, MapError, MapType, PerCpuArray, ProgramArray};
use aya::programs::trace_point::TracePointLinkId;
use aya::programs::uprobe::{UProbeAttachLocation, UProbeAttachPoint, UProbeLinkId, UProbeScope};
use aya::programs::{ProgramError, TracePoint, TracePointError, UProbe};
use p11scope_ebpf_common::{
    ARG_NONE, CFG_TASK_NEWTASK_OFFSETS, DISCOVERY_COUNTER_EXPORT_BOUNDED_READ_FAILURES,
    DISCOVERY_COUNTER_EXPORT_STATE_FAILURES, DISCOVERY_COUNTER_LOADER_HITS,
    DISCOVERY_COUNTER_LOADER_STATE_READ_FAILURES, DISCOVERY_COUNTER_RING_LOSS,
    FLAG_POLICY_AGGREGATE, FLAG_POLICY_ALLOWLISTED, FLAG_POLICY_UNSAFE_UNVALIDATED_METADATA,
    FUNCTION_NAME_MAX_BYTES, FunctionNameKey, MAX_DESCRIPTORS, PAUSE_ARMED, PauseKey,
    SlotSemantics, TAIL_CALLS_INTERFACE_WORKER_SLOT, TAIL_CALLS_TEMPLATE_SECOND_SLOT,
    attach_cookie, pack_task_newtask_offsets,
};
use pkcs11_proxy_ng_types::mechanism_registry::MechanismRegistry;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::mem::size_of_val;
use std::num::NonZeroU64;
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const BPF_F_RDONLY_PROG: u32 = 1 << 7;
const TASK_NEWTASK_FORMATS: [&str; 2] = [
    "/sys/kernel/tracing/events/task/task_newtask/format",
    "/sys/kernel/debug/tracing/events/task/task_newtask/format",
];

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

const BASE_POLICY_MAPS: [(&str, ExactMapMetadata); 7] = [
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
];
const FEATURE_POLICY_MAPS: [(&str, ExactMapMetadata); 1] = [(
    "ATTR_BOOL_BITS",
    map_metadata(MapType::Hash, 4, 4, 16, BPF_F_RDONLY_PROG),
)];
const TAIL_POLICY_MAP: &str = "TAIL_CALLS";
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
const UNSAFE_PROGRAMS: [&str; 4] = [
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
    let info = data
        .info()
        .with_context(|| format!("reading {name} map info"))?;
    let actual = ExactMapMetadata {
        map_type: info.map_type()?,
        key_size: info.key_size(),
        value_size: info.value_size(),
        max_entries: info.max_entries(),
        flags: info.map_flags(),
    };
    if actual != expected {
        bail!("{name} metadata {actual:?} differs from exact expected {expected:?}");
    }
    Ok(())
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

fn parse_task_newtask_field(
    line: &str,
    name: &str,
    expected_size: &str,
    expected_signed: &str,
) -> Result<Option<u16>> {
    let matching_fields = line
        .split(';')
        .filter_map(|part| part.trim().split_once(':'))
        .filter(|(key, value)| {
            key.trim() == "field" && value.split_whitespace().last() == Some(name)
        })
        .count();
    if matching_fields == 0 {
        return Ok(None);
    }
    if matching_fields != 1 {
        bail!("duplicate {name} field attribute in task_newtask format");
    }

    let mut offset = None;
    let mut size = None;
    let mut signed = None;
    for part in line.split(';') {
        let Some((key, value)) = part.trim().split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "offset" => {
                if offset.replace(value).is_some() {
                    bail!("duplicate offset attribute for {name}");
                }
            }
            "size" => {
                if size.replace(value).is_some() {
                    bail!("duplicate size attribute for {name}");
                }
            }
            "signed" => {
                if signed.replace(value).is_some() {
                    bail!("duplicate signed attribute for {name}");
                }
            }
            _ => {}
        }
    }
    let offset = offset
        .context("missing offset")?
        .parse::<usize>()
        .with_context(|| format!("invalid offset for {name}"))?;
    if size.context("missing size")? != expected_size {
        bail!("{name} must have size {expected_size}");
    }
    if signed.context("missing signedness")? != expected_signed {
        bail!("{name} has unexpected signedness");
    }
    let _end = offset
        .checked_add(expected_size.parse::<usize>().expect("fixed field size"))
        .context("field offset overflows tracepoint record")?;
    Ok(Some(u16::try_from(offset).with_context(|| {
        format!("offset outside packed form for {name}")
    })?))
}

fn parse_task_newtask_format(format: &str) -> Result<(u16, u16)> {
    let mut pid = None;
    let mut clone_flags = None;
    for line in format.lines() {
        for (name, size, signed, found) in [
            ("pid", "4", "1", &mut pid),
            ("clone_flags", "8", "0", &mut clone_flags),
        ] {
            if let Some(offset) = parse_task_newtask_field(line, name, size, signed)? {
                if found.replace(offset).is_some() {
                    bail!("duplicate {name} field in task_newtask format");
                }
            }
        }
    }
    Ok((
        pid.context("missing pid field in task_newtask format")?,
        clone_flags.context("missing clone_flags field in task_newtask format")?,
    ))
}

fn read_task_newtask_format_with(
    mut read: impl FnMut(&Path) -> std::io::Result<String>,
) -> Result<String> {
    let mut failures = Vec::new();
    let mut unavailable = true;
    for path in TASK_NEWTASK_FORMATS.map(Path::new) {
        match read(path) {
            Ok(format) => return Ok(format),
            Err(error) => {
                unavailable &= matches!(
                    error.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound
                );
                failures.push(format!("{}: {error}", path.display()));
            }
        }
    }
    let message = format!(
        "reading task/task_newtask format failed: {}",
        failures.join("; ")
    );
    if unavailable {
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, message).into());
    }
    bail!("{message}")
}

fn publish_task_newtask_offsets(ebpf: &mut Ebpf) -> Result<()> {
    let format = read_task_newtask_format_with(|path| std::fs::read_to_string(path))?;
    let (pid, clone_flags) = parse_task_newtask_format(&format)?;
    let expected = pack_task_newtask_offsets(pid, clone_flags);
    let mut config: Array<_, u64> = Array::try_from(ebpf.map_mut("CONFIG").context("CONFIG map")?)?;
    config.set(CFG_TASK_NEWTASK_OFFSETS, expected, 0)?;
    let config: Array<_, u64> = Array::try_from(ebpf.map("CONFIG").context("CONFIG map")?)?;
    if config.get(&CFG_TASK_NEWTASK_OFFSETS, 0)? != expected {
        bail!("CONFIG task_newtask offsets exact readback differs from parsed tracefs format");
    }
    Ok(())
}

fn freeze_map(name: &str, map: &Map) -> Result<()> {
    let data = policy_map_data(name, map)
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

    pub const fn uses_unsafe_decoders(self) -> bool {
        matches!(self, Self::UnsafeUnvalidatedMetadata)
    }
}

fn process_creation_capture_enabled(scope: &Scope, policy: CapturePolicy) -> bool {
    matches!(scope, Scope::Cgroup { .. }) && policy.uses_events()
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
        (Scope::Cgroup { .. }, Some(_)) => bail!("owned pause generation requires PID scope"),
    }
}

pub struct Session {
    pub(crate) ebpf: Ebpf,
    attach_failures: Vec<(u32, String)>,
    detach_failures: Vec<String>,
    /// Set once `detach_producers` detached every producer: only then is the
    /// `EVENTS` ring finite and a poll of it allowed to read it whole.
    producers_detached: bool,
    successful_static: BTreeSet<StaticEndpoint>,
    dynamic_attach_evidence: DynamicAttachEvidence,
    policy: CapturePolicy,
    uprobe_scope: UProbeScope,
    #[allow(dead_code)] // Task 8 drives the Task 7 pause coordinator.
    pause_key: Option<PauseKey>,
    lifecycle_tracking_unavailable: Option<String>,
    process_creation_tracking_unavailable: Option<String>,
    links: Vec<RegisteredLink>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AttachPreflight {
    pub(crate) lifecycle: bool,
    pub(crate) scope: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum LifecycleAttachOutcome<T> {
    Attached(Vec<(&'static str, T)>),
    Degraded(String),
}

fn expected_tracefs_id_path(program: &str, path: &Path) -> bool {
    let category = if program == "task_newtask" {
        "task"
    } else {
        "sched"
    };
    ["/sys/kernel/tracing", "/sys/kernel/debug/tracing"]
        .into_iter()
        .any(|root| {
            path == Path::new(root)
                .join("events")
                .join(category)
                .join(program)
                .join("id")
        })
}

fn tracefs_lifecycle_failure(error: &anyhow::Error, program: &str) -> Option<String> {
    match error.downcast_ref::<ProgramError>()? {
        ProgramError::IOError(error)
            if error.kind() == std::io::ErrorKind::Other
                && error.to_string() == "tracefs not found" =>
        {
            Some("tracefs not found".into())
        }
        ProgramError::TracePointError(TracePointError::FileError { filename, io_error })
            if expected_tracefs_id_path(program, filename)
                && matches!(
                    io_error.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound
                ) =>
        {
            Some(format!(
                "tracefs id file {}: {io_error}",
                filename.display()
            ))
        }
        _ => None,
    }
}

/// Attaches the two all-session lifecycle programs as one tier. A future raw
/// tracepoint implementation can replace this mechanism without changing its
/// callers or its all-or-nothing lifecycle contract.
fn attach_lifecycle_with<S, T>(
    state: &mut S,
    owned_run: bool,
    mut attach: impl FnMut(&mut S, &'static str) -> Result<T>,
    mut detach: impl FnMut(&mut S, &'static str, T) -> Result<()>,
) -> Result<LifecycleAttachOutcome<T>> {
    let mut links = Vec::new();
    for program in ["sched_process_exec", "sched_process_exit"] {
        match attach(state, program) {
            Ok(link) => links.push((program, link)),
            Err(error) => {
                let tracefs = tracefs_lifecycle_failure(&error, program);
                let attach_failure = format!("{error:#}");
                for (attached_program, link) in links.into_iter().rev() {
                    if let Err(rollback) =
                        detach(state, attached_program, link).with_context(|| {
                            format!("rolling back {attached_program} after {program} failed")
                        })
                    {
                        bail!("attaching {program}: {attach_failure}; {rollback:#}");
                    }
                }
                let error = error.context(format!("attaching {program}"));
                if let Some(cause) = tracefs {
                    let fact = format!("live lifecycle tracking unavailable: {cause}");
                    if owned_run {
                        return Err(error.context(format!(
                            "owned run requires tracefs lifecycle tracking; run as root or remount tracefs with gid=<observer-group> and mode=0750: {fact}"
                        )));
                    }
                    return Ok(LifecycleAttachOutcome::Degraded(fact));
                }
                return Err(error);
            }
        }
    }
    Ok(LifecycleAttachOutcome::Attached(links))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProducerProgram {
    UProbe(&'static str),
    TracePoint(&'static str),
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
    TracePoint {
        program: &'static str,
        id: TracePointLinkId,
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
            Self::UProbe { program, .. } | Self::DynamicUProbe { program, .. } => {
                ProducerProgram::UProbe(program)
            }
            Self::TracePoint { program, .. } => ProducerProgram::TracePoint(program),
        }
    }

    fn slot(&self) -> Option<u32> {
        match self {
            Self::UProbe { slot, .. } => Some(*slot),
            Self::TracePoint { .. } | Self::DynamicUProbe { .. } => None,
        }
    }

    fn context(&self) -> Option<LoaderContextId> {
        match self {
            Self::DynamicUProbe { context, .. } => Some(*context),
            Self::UProbe { .. } | Self::TracePoint { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct CounterSnapshot {
    pub(crate) ring_loss: u64,
    pub(crate) export_state_failures: u64,
    pub(crate) export_bounded_read_failures: u64,
    pub(crate) loader_hits: u64,
    pub(crate) loader_state_read_failures: u64,
}

impl CounterSnapshot {
    pub(crate) fn replace_with(&mut self, next: Self) -> bool {
        let nondecreasing = next.ring_loss >= self.ring_loss
            && next.export_state_failures >= self.export_state_failures
            && next.export_bounded_read_failures >= self.export_bounded_read_failures
            && next.loader_hits >= self.loader_hits
            && next.loader_state_read_failures >= self.loader_state_read_failures;
        if nondecreasing {
            *self = next;
        }
        nondecreasing
    }
}

fn counter_snapshot_with(mut read: impl FnMut(u32) -> Result<u64>) -> Result<CounterSnapshot> {
    Ok(CounterSnapshot {
        ring_loss: read(DISCOVERY_COUNTER_RING_LOSS)?,
        export_state_failures: read(DISCOVERY_COUNTER_EXPORT_STATE_FAILURES)?,
        export_bounded_read_failures: read(DISCOVERY_COUNTER_EXPORT_BOUNDED_READ_FAILURES)?,
        loader_hits: read(DISCOVERY_COUNTER_LOADER_HITS)?,
        loader_state_read_failures: read(DISCOVERY_COUNTER_LOADER_STATE_READ_FAILURES)?,
    })
}

#[cfg(test)]
fn detach_producers_with(
    policy: CapturePolicy,
    fork_attached: bool,
    mut detach: impl FnMut(ProducerProgram) -> Result<()>,
) -> Result<()> {
    let mut first_error = None;
    let mut detach_one = |producer| {
        if let Err(error) = detach(producer) {
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    };
    detach_one(ProducerProgram::UProbe("p11_entry"));
    if policy.uses_unsafe_decoders() {
        for name in [
            "p11_entry_template",
            "p11_entry_template_types",
            "p11_entry_template_pair",
        ] {
            detach_one(ProducerProgram::UProbe(name));
        }
    }
    if fork_attached {
        detach_one(ProducerProgram::TracePoint("task_newtask"));
    }
    detach_one(ProducerProgram::UProbe("p11_return"));
    first_error.map_or(Ok(()), Err)
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
        ProducerProgram::UProbe("p11_entry_template") => 1,
        ProducerProgram::UProbe("p11_entry_template_types") => 2,
        ProducerProgram::UProbe("p11_entry_template_pair") => 3,
        ProducerProgram::TracePoint("task_newtask") => 4,
        ProducerProgram::UProbe("p11_return") => 5,
        _ => 6,
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

fn entry_program(semantics: &SlotSemantics, policy: CapturePolicy) -> &'static str {
    if !policy.uses_unsafe_decoders() {
        return "p11_entry";
    }
    if semantics.template1_arg != ARG_NONE {
        "p11_entry_template_pair"
    } else if semantics.semantic_flags & p11scope_ebpf_common::semantic_flags::TEMPLATE0_TYPES_ONLY
        != 0
    {
        "p11_entry_template_types"
    } else if semantics.template0_arg != ARG_NONE {
        "p11_entry_template"
    } else {
        "p11_entry"
    }
}

struct AttachOutcome {
    successful: BTreeSet<StaticEndpoint>,
    failures: Vec<(u32, String)>,
    completed: Vec<SlotCompletion>,
}

type SlotCompletion = (u32, Option<u64>);
type TargetAttachResult = (Vec<u32>, Vec<SlotCompletion>);
type ReplacementAttachResult = (Vec<SlotCompletion>, bool);

fn export_programs(abi: HookAbi) -> (&'static str, &'static str) {
    match abi {
        HookAbi::FunctionList => ("function_list_entry", "function_list_return"),
        HookAbi::InterfaceList => ("interface_list_entry", "interface_list_return"),
        HookAbi::Interface => ("interface_entry", "interface_return"),
    }
}

fn static_endpoint(program: &str, slot: u32) -> Option<StaticEndpoint> {
    match program {
        "p11_return" => Some((slot, ProbeSide::Return)),
        "p11_entry"
        | "p11_entry_template"
        | "p11_entry_template_types"
        | "p11_entry_template_pair" => Some((slot, ProbeSide::Entry)),
        _ => None,
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
fn attach_targets_with(
    slots: &[Slot],
    policy: CapturePolicy,
    mut attach: impl FnMut(&'static str, &Slot) -> Result<()>,
    mut completed_at: impl FnMut(&Slot) -> Option<u64>,
) -> AttachOutcome {
    let mut successful = BTreeSet::new();
    let mut failures = Vec::new();
    let mut completed = Vec::new();
    let mut return_attached = BTreeSet::new();
    for slot in slots {
        match attach("p11_return", slot) {
            Ok(()) => {
                successful.insert(
                    static_endpoint("p11_return", slot.index)
                        .expect("p11_return is a static endpoint"),
                );
                return_attached.insert(slot.index);
            }
            Err(error) => failures.push((slot.index, format!("{error:#}"))),
        }
    }

    let entry_programs: &[&str] = if policy.uses_unsafe_decoders() {
        &[
            "p11_entry",
            "p11_entry_template",
            "p11_entry_template_types",
            "p11_entry_template_pair",
        ]
    } else {
        &["p11_entry"]
    };
    for program in entry_programs {
        for slot in slots {
            if !return_attached.contains(&slot.index)
                || entry_program(&slot.semantics, policy) != *program
            {
                continue;
            }
            match attach(program, slot) {
                Ok(()) => {
                    successful.insert(
                        static_endpoint(program, slot.index)
                            .expect("selected entry program is a static endpoint"),
                    );
                    completed.push((slot.index, completed_at(slot)));
                }
                Err(error) => failures.push((slot.index, format!("{error:#}"))),
            }
        }
    }
    AttachOutcome {
        successful,
        failures,
        completed,
    }
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

fn publish_descriptors(ebpf: &mut Ebpf) -> Result<()> {
    let expected = crate::kinds::DESCRIPTORS.to_vec();
    let mut semantics: Array<_, SlotSemantics> =
        Array::try_from(ebpf.map_mut("DESCRIPTORS").context("DESCRIPTORS map")?)?;
    for (index, value) in expected.iter().copied().enumerate() {
        semantics.set(index as u32, value, 0)?;
    }
    let semantics: Array<_, SlotSemantics> =
        Array::try_from(ebpf.map("DESCRIPTORS").context("DESCRIPTORS map")?)?;
    let actual = semantics.iter().collect::<Result<Vec<_>, _>>()?;
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

fn freeze_published_maps(ebpf: &Ebpf) -> Result<()> {
    for (name, _) in BASE_POLICY_MAPS {
        if matches!(name, "DESCRIPTORS" | TAIL_POLICY_MAP) {
            continue;
        }
        freeze_map(name, ebpf.map(name).with_context(|| format!("{name} map"))?)?;
    }
    for (name, _) in FEATURE_POLICY_MAPS {
        if let Some(map) = ebpf.map(name) {
            freeze_map(name, map)?;
        }
    }
    Ok(())
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

fn validate_runtime_maps(ebpf: &Ebpf) -> Result<()> {
    validate_runtime_map(
        ebpf,
        "DISCOVERY",
        MapType::RingBuf,
        0,
        0,
        p11scope_ebpf_common::DISCOVERY_BYTES,
    )?;
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
    let expected = expected_programs(unsafe_enabled);
    let actual: BTreeSet<_> = ebpf.programs().map(|(name, _)| name).collect();
    if actual != expected {
        bail!("eBPF program inventory {actual:?} differs from {expected:?}");
    }
    Ok(())
}

fn publish_and_freeze_tail_calls(ebpf: &mut Ebpf, enabled: bool) -> Result<()> {
    let (worker_fd, worker_id) = {
        let worker: &UProbe = ebpf
            .program("interface_list_worker")
            .context("program interface_list_worker missing from object")?
            .try_into()?;
        (worker.fd()?.try_clone()?, worker.info()?.id())
    };
    let second = if enabled {
        let second: &UProbe = ebpf
            .program("p11_entry_template_second")
            .context("program p11_entry_template_second missing from object")?
            .try_into()?;
        Some((second.fd()?.try_clone()?, second.info()?.id()))
    } else {
        None
    };
    {
        let mut tails: ProgramArray<_> =
            ProgramArray::try_from(ebpf.map_mut(TAIL_POLICY_MAP).context("TAIL_CALLS map")?)?;
        tails.set(TAIL_CALLS_INTERFACE_WORKER_SLOT, &worker_fd, 0)?;
        if let Some((second_fd, _)) = second.as_ref() {
            tails.set(TAIL_CALLS_TEMPLATE_SECOND_SLOT, second_fd, 0)?;
        }
    }
    let map = ebpf.map(TAIL_POLICY_MAP).context("TAIL_CALLS map")?;
    let actual_worker = program_array_id(TAIL_POLICY_MAP, map, TAIL_CALLS_INTERFACE_WORKER_SLOT)?;
    if actual_worker != Some(worker_id) {
        bail!(
            "TAIL_CALLS worker exact readback id {actual_worker:?} differs from loaded program {worker_id}"
        );
    }
    let actual_second = program_array_id(TAIL_POLICY_MAP, map, TAIL_CALLS_TEMPLATE_SECOND_SLOT)?;
    let expected_second = second.as_ref().map(|(_, id)| *id);
    if actual_second != expected_second {
        bail!(
            "TAIL_CALLS template-second exact readback id {actual_second:?} differs from expected {expected_second:?}"
        );
    }
    freeze_map(TAIL_POLICY_MAP, map)
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
docs/notes/phase5-unsupported.md for what each looks like when observed.";

fn unsupported_environment_context(error: anyhow::Error) -> anyhow::Error {
    error.context(UNSUPPORTED_ENV_HINT)
}

impl Session {
    pub(crate) const fn capture_policy(&self) -> CapturePolicy {
        self.policy
    }

    pub(crate) fn start(
        plan: &AttachPlan,
        scope: &Scope,
        objects: &PinnedObjects,
        policy: CapturePolicy,
        pause_generation: Option<OwnedPauseGeneration>,
    ) -> Result<Self> {
        let pause_key = pause_key_for(scope, pause_generation.as_ref())?;
        if !objects.check_unchanged().map_err(anyhow::Error::msg)? {
            bail!(
                "a pinned provider object changed before attach; refusing to observe changed bytes"
            );
        }
        let mut session =
            Self::start_inner(scope, policy, pause_key).map_err(unsupported_environment_context)?;
        session
            .attach_plan(plan, objects)
            .map_err(unsupported_environment_context)?;
        // The error path drops `session`, which detaches every probe.
        if !objects.check_unchanged().map_err(anyhow::Error::msg)? {
            bail!(
                "a pinned provider object changed while attaching; refusing to observe changed bytes"
            );
        }
        Ok(session)
    }

    /// Exercises the real embedded object, policy maps, program inventory,
    /// requested scope, process-creation boundary, and exec/exit links. Dropping the local
    /// session detaches every link before this finite result is returned.
    pub(crate) fn preflight(scope: &Scope) -> Result<AttachPreflight> {
        let session = Self::start_inner(scope, CapturePolicy::Allowlisted, None)?;
        Ok(AttachPreflight {
            lifecycle: session.lifecycle_tracking_unavailable.is_none(),
            scope: session.process_creation_tracking_unavailable.is_none(),
        })
    }

    fn start_inner(
        scope: &Scope,
        policy: CapturePolicy,
        pause_key: Option<PauseKey>,
    ) -> Result<Self> {
        if policy.uses_unsafe_decoders() && !cfg!(feature = "unsafe-unvalidated-metadata") {
            bail!("unsafe-unvalidated-metadata policy is absent from this eBPF object");
        }
        let mut ebpf = Ebpf::load(crate::EBPF_OBJECT).context("loading BPF object")?;
        let object_has_unsafe = cfg!(feature = "unsafe-unvalidated-metadata");
        let unsafe_enabled = object_has_unsafe && policy.uses_unsafe_decoders();
        validate_policy_maps(&ebpf, object_has_unsafe)
            .context("validating exact policy-map metadata")?;
        validate_runtime_maps(&ebpf).context("validating live-discovery runtime maps")?;
        validate_program_inventory(&ebpf, object_has_unsafe)
            .context("validating exact eBPF program inventory")?;
        let generation_token = pause_key.map(|key| key.generation_token);
        crate::scope::publish(&mut ebpf, scope, policy, generation_token)
            .context("publishing scope and capture policy")?;
        let process_creation_enabled = process_creation_capture_enabled(scope, policy);
        let mut process_creation_tracking_unavailable = None;
        if process_creation_enabled
            && let Err(error) =
                publish_task_newtask_offsets(&mut ebpf).context("publishing task_newtask offsets")
        {
            if error.downcast_ref::<std::io::Error>().is_some_and(|error| {
                matches!(
                    error.kind(),
                    std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound
                )
            }) {
                process_creation_tracking_unavailable = Some(format!(
                    "live process-creation tracking unavailable: {}",
                    error.root_cause()
                ));
            } else {
                return Err(error);
            }
        }
        publish_descriptors(&mut ebpf).context("publishing DESCRIPTORS")?;
        publish_async_catalog(&mut ebpf).context("publishing ASYNC_FUNCTIONS")?;
        {
            // Embedded defaults: this binary ships statically and has no
            // config-file plumbing yet, so `None` is the only reachable
            // path today. A future task can thread a path through here
            // without touching the publish-before-attach placement.
            let registry = MechanismRegistry::load(None)
                .map_err(|e| anyhow!("loading mechanism registry: {e}"))?;
            crate::shapes::publish(&mut ebpf, &registry).context("publishing MECH_SHAPE")?;
        }
        publish_attribute_catalog(&mut ebpf, unsafe_enabled)
            .context("publishing ATTR_BOOL_BITS")?;
        freeze_published_maps(&ebpf).context("freezing published policy maps")?;

        let uprobe_scope = match scope {
            Scope::Pid(pid) => UProbeScope::OneProcess(
                std::num::NonZeroU32::new(*pid).context("pid must be non-zero")?,
            ),
            // Cgroup scoping is enforced in BPF, so the probe itself is
            // process-wide and the filter map decides.
            Scope::Cgroup { .. } => UProbeScope::AllProcesses,
        };

        let programs = expected_programs(object_has_unsafe);
        for prog_name in programs {
            if matches!(
                prog_name,
                "task_newtask" | "sched_process_exec" | "sched_process_exit"
            ) {
                let prog: &mut TracePoint = ebpf
                    .program_mut(prog_name)
                    .with_context(|| format!("program {prog_name} missing from object"))?
                    .try_into()?;
                prog.load()
                    .with_context(|| format!("loading {prog_name}"))?;
            } else {
                let prog: &mut UProbe = ebpf
                    .program_mut(prog_name)
                    .with_context(|| format!("program {prog_name} missing from object"))?
                    .try_into()?;
                prog.load()
                    .with_context(|| format!("loading {prog_name}"))?;
            }
        }
        // Linux can constant-fold frozen arrays, but returns its internal
        // ENOTSUPP for direct reads before the program is loaded.
        // Loading first avoids that kernel path; freezing still precedes every
        // attachment, so no probe can observe mutable policy.
        freeze_map(
            "DESCRIPTORS",
            ebpf.map("DESCRIPTORS").context("DESCRIPTORS map")?,
        )
        .context("freezing DESCRIPTORS")?;
        publish_and_freeze_tail_calls(&mut ebpf, unsafe_enabled)
            .context("publishing and freezing TAIL_CALLS")?;

        let mut links = Vec::new();
        if process_creation_enabled && process_creation_tracking_unavailable.is_none() {
            let process_creation: &mut TracePoint = ebpf
                .program_mut("task_newtask")
                .context("program task_newtask missing from object")?
                .try_into()?;
            match process_creation.attach("task", "task_newtask") {
                Ok(id) => links.push(RegisteredLink::TracePoint {
                    program: "task_newtask",
                    id,
                }),
                Err(error) => {
                    let error = anyhow::Error::from(error);
                    if let Some(cause) = tracefs_lifecycle_failure(&error, "task_newtask") {
                        process_creation_tracking_unavailable = Some(format!(
                            "live process-creation tracking unavailable: {cause}"
                        ));
                    } else {
                        return Err(error.context("attaching task_newtask"));
                    }
                }
            }
        }
        let lifecycle_tracking_unavailable = match attach_lifecycle_with(
            &mut ebpf,
            pause_key.is_some(),
            |ebpf, program| {
                let tracepoint: &mut TracePoint = ebpf
                    .program_mut(program)
                    .with_context(|| format!("program {program} missing from object"))?
                    .try_into()?;
                tracepoint.attach("sched", program).map_err(Into::into)
            },
            |ebpf, program, id| {
                let tracepoint: &mut TracePoint = ebpf
                    .program_mut(program)
                    .with_context(|| format!("program {program} missing during rollback"))?
                    .try_into()?;
                tracepoint.detach(id).map_err(Into::into)
            },
        )? {
            LifecycleAttachOutcome::Attached(lifecycle_links) => {
                links.extend(
                    lifecycle_links
                        .into_iter()
                        .map(|(program, id)| RegisteredLink::TracePoint { program, id }),
                );
                None
            }
            LifecycleAttachOutcome::Degraded(fact) => Some(fact),
        };

        Ok(Self {
            ebpf,
            attach_failures: vec![],
            detach_failures: vec![],
            producers_detached: false,
            successful_static: BTreeSet::new(),
            dynamic_attach_evidence: DynamicAttachEvidence::default(),
            policy,
            uprobe_scope,
            pause_key,
            lifecycle_tracking_unavailable,
            process_creation_tracking_unavailable,
            links,
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
        counter_snapshot_with(read)
    }

    pub(crate) fn preflight_targets(
        &self,
        targets: &[Slot],
        objects: &PinnedObjects,
    ) -> Result<()> {
        if !objects.check_unchanged().map_err(anyhow::Error::msg)? {
            bail!("a pinned provider object changed before live attachment");
        }
        for target in targets {
            objects
                .attach_path_for(target.object)
                .map_err(anyhow::Error::msg)?;
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
        match self
            .dynamic_attach_evidence
            .record(probe.attach(point, &path, scope))
        {
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
        let return_id = {
            let probe: &mut UProbe = self
                .ebpf
                .program_mut(return_program)
                .with_context(|| format!("program {return_program} missing from object"))?
                .try_into()?;
            self.dynamic_attach_evidence
                .record(probe.attach(point(), &path, scope))
                .map_err(|error| {
                    anyhow!(
                        "{return_program} at object {:?}+{file_offset:#x}: {}",
                        object,
                        error_chain(&error)
                    )
                })?
        };
        let entry_id = {
            let probe: &mut UProbe = self
                .ebpf
                .program_mut(entry_program)
                .with_context(|| format!("program {entry_program} missing from object"))?
                .try_into()?;
            match self
                .dynamic_attach_evidence
                .record(probe.attach(point(), &path, scope))
            {
                Ok(id) => id,
                Err(error) => {
                    let message = format!(
                        "{entry_program} at object {:?}+{file_offset:#x}: {}",
                        object,
                        error_chain(&error)
                    );
                    let probe: &mut UProbe = self
                        .ebpf
                        .program_mut(return_program)
                        .with_context(|| {
                            format!("program {return_program} missing during partial detach")
                        })?
                        .try_into()?;
                    if let Err(error) = probe.detach(return_id) {
                        self.detach_failures.push(format!(
                            "detaching partial {return_program}: {}",
                            error_chain(&error)
                        ));
                    }
                    return Err(anyhow!(message));
                }
            }
        };
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
            RegisteredLink::UProbe { .. } | RegisteredLink::TracePoint { .. } => (context, None),
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
        let attach_paths: BTreeMap<_, _> = targets
            .iter()
            // By capture-local pinned ID only. There is deliberately no by-path
            // fallback: a target pathname can name a different object here.
            .map(|slot| {
                objects
                    .attach_path_for(slot.object)
                    .map(|path| (slot.index, path))
                    .map_err(anyhow::Error::msg)
            })
            .collect::<Result<_>>()?;
        let scope = self.uprobe_scope;
        let ebpf = &mut self.ebpf;
        let links = &mut self.links;
        let outcome = attach_targets_with(
            targets,
            self.policy,
            |program, slot| {
                let path = attach_paths
                    .get(&slot.index)
                    .expect("every selected target has a retained pinned path");
                let point = UProbeAttachPoint {
                    location: UProbeAttachLocation::AbsoluteOffset(slot.file_offset),
                    cookie: Some(attach_cookie(slot.index, slot.descriptor_index)),
                };
                let prog: &mut UProbe = ebpf
                    .program_mut(program)
                    .with_context(|| format!("program {program} missing from object"))?
                    .try_into()?;
                match prog.attach(point, path, scope) {
                    Ok(id) => {
                        links.push(RegisteredLink::UProbe {
                            program,
                            slot: slot.index,
                            id,
                        });
                        Ok(())
                    }
                    Err(error) => Err(anyhow!(
                        "{program} at {}+{:#x}: {}",
                        slot.object_path,
                        slot.file_offset,
                        error_chain(&error)
                    )),
                }
            },
            |_| monotonic_ns(),
        );
        let AttachOutcome {
            successful,
            failures,
            completed,
        } = outcome;
        self.successful_static.extend(successful);
        let failed: Vec<_> = failures.iter().map(|(slot, _)| *slot).collect();
        self.attach_failures.extend(failures);
        Ok((failed, completed))
    }

    /// Applies the attachment half of a descriptor downgrade after the caller
    /// has detached the old links and synchronized semantic consumers. A failed
    /// replacement cannot fall back to the frozen descriptor it replaced.
    pub fn replace_targets(
        &mut self,
        plan: &mut AttachPlan,
        replace: &[Slot],
        objects: &PinnedObjects,
    ) -> Result<ReplacementAttachResult> {
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
        Ok((completed, detach.is_err()))
    }

    /// Detaches all slot links selected by a finite retirement/replacement
    /// delta. Each attempt is made even if an earlier Aya detach failed.
    pub fn detach_slots(&mut self, slots: &[Slot]) -> Result<()> {
        let slots: BTreeSet<_> = slots.iter().map(|slot| slot.index).collect();
        self.detach_links(|link| link.slot().is_some_and(|slot| slots.contains(&slot)))
    }

    /// Detach every event/map producer while keeping the maps and ring reader
    /// available for a best-effort terminal drain and snapshot. Entry probes
    /// go first so fewer calls are stranded before the return probes are
    /// removed last. Kernel detach does not wait for callbacks already running
    /// on another CPU; callers must not claim that the terminal drain is final.
    pub fn detach_producers(&mut self) -> Result<()> {
        let detached = self.detach_links(|_| true);
        self.producers_detached = detached.is_ok();
        detached
    }

    /// The bound the next `EVENTS` poll gets — see `events::poll_quantum`.
    pub fn live_poll_quantum(&self) -> Option<usize> {
        events::poll_quantum(self.producers_detached)
    }

    fn has_slot_link(&self, slot: u32) -> bool {
        self.links.iter().any(|link| link.slot() == Some(slot))
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
        match link {
            RegisteredLink::UProbe { program, id, .. } => (|| {
                let probe: &mut UProbe = self
                    .ebpf
                    .program_mut(program)
                    .with_context(|| format!("program {program} missing during detach"))?
                    .try_into()?;
                probe
                    .detach(id)
                    .with_context(|| format!("detaching {program}"))
            })(),
            RegisteredLink::TracePoint { program, id } => (|| {
                let tracepoint: &mut TracePoint = self
                    .ebpf
                    .program_mut(program)
                    .with_context(|| format!("program {program} missing during detach"))?
                    .try_into()?;
                tracepoint
                    .detach(id)
                    .with_context(|| format!("detaching {program}"))
            })(),
            RegisteredLink::DynamicUProbe { program, id, .. } => (|| {
                let probe: &mut UProbe = self
                    .ebpf
                    .program_mut(program)
                    .with_context(|| format!("program {program} missing during detach"))?
                    .try_into()?;
                probe
                    .detach(id)
                    .with_context(|| format!("detaching {program}"))
            })(),
        }
    }

    pub fn event_drain(&mut self) -> Result<events::Drain<'_>> {
        events::Drain::new(&mut self.ebpf)
    }

    pub(crate) fn discovery_dequeue(&mut self) -> Result<Option<events::DiscoveryItem>> {
        let mut drain = events::DiscoveryDrain::new(&mut self.ebpf)?;
        Ok(drain.dequeue())
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

    pub(crate) fn dynamic_per_offset_attached(&self) -> bool {
        self.dynamic_attach_evidence.successful()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.detach_producers();
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
}

#[cfg(test)]
mod tracepoint_format {
    use super::{TASK_NEWTASK_FORMATS, parse_task_newtask_format, read_task_newtask_format_with};

    const VALID: &str = "field:pid_t pid; offset:32; size:4; signed:1;\nfield:unsigned long clone_flags; offset:56; size:8; signed:0;\n";

    #[test]
    fn tracepoint_format_parses_shifted_task_newtask_offsets() {
        assert_eq!(parse_task_newtask_format(VALID).unwrap(), (32, 56));
    }

    #[test]
    fn tracepoint_format_rejects_malformed_and_unrepresentable_fields() {
        let cases = [
            (
                "missing pid",
                VALID.replace("field:pid_t pid; offset:32; size:4; signed:1;\n", ""),
            ),
            (
                "missing clone_flags",
                VALID.replace(
                    "field:unsigned long clone_flags; offset:56; size:8; signed:0;\n",
                    "",
                ),
            ),
            (
                "duplicate pid",
                format!("{VALID}field:pid_t pid; offset:64; size:4; signed:1;\n"),
            ),
            (
                "pid size other than four",
                VALID.replace("size:4", "size:8"),
            ),
            ("pid unsigned field", VALID.replace("signed:1", "signed:0")),
            (
                "clone flags size other than eight",
                VALID.replace("size:8", "size:4"),
            ),
            (
                "clone flags signed field",
                VALID.replace("signed:0", "signed:1"),
            ),
            ("negative offset", VALID.replace("offset:32", "offset:-1")),
            (
                "offset outside CONFIG packed form",
                VALID.replace("offset:32", "offset:65536"),
            ),
            ("missing offset", VALID.replace("offset:32; ", "")),
            ("missing size", VALID.replace("size:4; ", "")),
            ("missing signedness", VALID.replace("signed:1;", "")),
            (
                "duplicate offset",
                VALID.replace("offset:32;", "offset:32; offset:33;"),
            ),
            (
                "duplicate size",
                VALID.replace("size:4;", "size:4; size:4;"),
            ),
            (
                "duplicate signedness",
                VALID.replace("signed:1;", "signed:1; signed:1;"),
            ),
            (
                "malformed offset",
                VALID.replace("offset:32", "offset:32junk"),
            ),
        ];

        for (reason, format) in cases {
            assert!(
                parse_task_newtask_format(&format).is_err(),
                "accepted {reason}"
            );
        }
    }

    #[test]
    fn tracepoint_format_reader_falls_back_to_debugfs() {
        let mut visited = Vec::new();
        let format = read_task_newtask_format_with(|path| {
            visited.push(path.to_path_buf());
            if path == std::path::Path::new(TASK_NEWTASK_FORMATS[1]) {
                Ok(VALID.to_string())
            } else {
                Err(std::io::Error::from(std::io::ErrorKind::NotFound))
            }
        })
        .unwrap();
        assert_eq!(format, VALID);
        assert_eq!(visited.len(), 2);
    }

    #[test]
    fn tracepoint_format_reader_reports_both_failed_paths() {
        let error = read_task_newtask_format_with(|path| {
            if path == std::path::Path::new(TASK_NEWTASK_FORMATS[0]) {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "primary tracefs denied",
                ))
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "debugfs tracepoint missing",
                ))
            }
        })
        .unwrap_err()
        .to_string();
        for expected in [
            TASK_NEWTASK_FORMATS[0],
            TASK_NEWTASK_FORMATS[1],
            "primary tracefs denied",
            "debugfs tracepoint missing",
        ] {
            assert!(error.contains(expected), "{error}");
        }
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
    use super::*;

    #[test]
    fn task_8d_dynamic_attach_evidence_retains_partial_and_detached_success() {
        let mut failed = DynamicAttachEvidence::default();
        assert_eq!(
            failed.record::<u8, _>(Err("return failed")),
            Err("return failed")
        );
        assert!(
            !failed.successful(),
            "a failed attach is not lifetime evidence"
        );

        let mut evidence = DynamicAttachEvidence::default();
        let mut detached = Vec::new();

        let return_id = evidence.record::<_, &str>(Ok(1)).unwrap();
        assert_eq!(
            evidence.record::<u8, _>(Err("entry failed")),
            Err("entry failed")
        );
        detached.push(return_id);

        assert_eq!(detached, [1]);
        assert!(evidence.successful());
        detached.push(evidence.record::<_, &str>(Ok(2)).unwrap());
        assert_eq!(detached, [1, 2]);
        assert!(
            evidence.successful(),
            "terminal detach cannot erase lifetime evidence"
        );
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

    #[test]
    fn failed_dynamic_detach_is_sticky_and_blocks_replacement() {
        let attempted = std::cell::RefCell::new(Vec::new());
        let errors = detach_selected_with(
            vec![
                (ProducerProgram::UProbe("dynamic"), 1u8),
                (ProducerProgram::UProbe("dynamic"), 2),
            ],
            |link| {
                attempted.borrow_mut().push(link);
                if link == 1 {
                    anyhow::bail!("injected dynamic detach failure")
                }
                Ok(())
            },
        );

        assert_eq!(*attempted.borrow(), [1, 2], "every detach is one-shot");
        assert_eq!(errors.len(), 1);
    }

    #[test]
    fn only_static_slot_programs_have_endpoint_identities() {
        assert_eq!(
            static_endpoint("p11_return", 7),
            Some((7, ProbeSide::Return))
        );
        for program in [
            "p11_entry",
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
    fn optional_lifecycle_tier_degrades_for_typed_tracefs_discovery_loss() {
        let mut state = ();
        let outcome = attach_lifecycle_with::<_, ()>(
            &mut state,
            false,
            |_, program| {
                assert_eq!(program, "sched_process_exec");
                Err(
                    aya::programs::ProgramError::IOError(io::Error::other("tracefs not found"))
                        .into(),
                )
            },
            |_, _, _| Ok(()),
        )
        .unwrap();

        assert_eq!(
            outcome,
            LifecycleAttachOutcome::Degraded(
                "live lifecycle tracking unavailable: tracefs not found".into()
            )
        );
    }

    #[test]
    fn process_creation_capture_is_cgroup_only() {
        let cgroup = Scope::Cgroup {
            id: 1,
            path: "/".into(),
            dir: Arc::new(File::open("/").unwrap()),
        };
        for (scope, policy, expected) in [
            (Scope::Pid(7), CapturePolicy::Allowlisted, false),
            (
                Scope::Pid(7),
                CapturePolicy::UnsafeUnvalidatedMetadata,
                false,
            ),
            (Scope::Pid(7), CapturePolicy::AggregateOnly, false),
            (cgroup, CapturePolicy::Allowlisted, true),
        ] {
            assert_eq!(process_creation_capture_enabled(&scope, policy), expected);
        }
    }

    #[test]
    fn optional_lifecycle_tier_rolls_back_the_first_link_when_second_is_unavailable() {
        let mut detached = Vec::new();
        let outcome = attach_lifecycle_with(
            &mut detached,
            false,
            |_, program| match program {
                "sched_process_exec" => Ok(program),
                "sched_process_exit" => Err(aya::programs::ProgramError::IOError(
                    io::Error::other("tracefs not found"),
                )
                .into()),
                _ => unreachable!(),
            },
            |detached, _, link| {
                detached.push(link);
                Ok(())
            },
        )
        .unwrap();

        assert!(matches!(outcome, LifecycleAttachOutcome::Degraded(_)));
        assert_eq!(detached, ["sched_process_exec"]);
    }

    #[test]
    fn lifecycle_tier_rollback_failure_stays_fatal_and_retains_both_causes() {
        let mut state = ();
        let error = attach_lifecycle_with(
            &mut state,
            false,
            |_, program| match program {
                "sched_process_exec" => Ok(()),
                "sched_process_exit" => {
                    Err(ProgramError::IOError(io::Error::other("tracefs not found")).into())
                }
                _ => unreachable!(),
            },
            |_, _, _| anyhow::bail!("injected rollback failure"),
        )
        .unwrap_err();
        let rendered = format!("{error:#}");

        assert!(rendered.contains("tracefs not found"));
        assert!(rendered.contains("injected rollback failure"));
    }

    #[test]
    fn lifecycle_tier_classifies_only_expected_tracefs_id_file_access() {
        for kind in [io::ErrorKind::PermissionDenied, io::ErrorKind::NotFound] {
            let error =
                anyhow::Error::from(ProgramError::TracePointError(TracePointError::FileError {
                    filename: PathBuf::from(
                        "/sys/kernel/tracing/events/sched/sched_process_exec/id",
                    ),
                    io_error: io::Error::from(kind),
                }));
            assert!(tracefs_lifecycle_failure(&error, "sched_process_exec").is_some());
        }

        let unexpected =
            anyhow::Error::from(ProgramError::TracePointError(TracePointError::FileError {
                filename: PathBuf::from("/tmp/not-tracefs/id"),
                io_error: io::Error::from(io::ErrorKind::PermissionDenied),
            }));
        assert!(tracefs_lifecycle_failure(&unexpected, "sched_process_exec").is_none());

        let malformed_id =
            anyhow::Error::from(ProgramError::TracePointError(TracePointError::FileError {
                filename: PathBuf::from(
                    "/sys/kernel/tracing/events/sched/sched_process_exec/id.bak",
                ),
                io_error: io::Error::from(io::ErrorKind::PermissionDenied),
            }));
        assert!(tracefs_lifecycle_failure(&malformed_id, "sched_process_exec").is_none());
    }

    #[test]
    fn unsupported_environment_context_preserves_program_error() {
        let error = unsupported_environment_context(
            ProgramError::IOError(io::Error::other("tracefs not found")).into(),
        );

        assert!(format!("{error:#}").contains(UNSUPPORTED_ENV_HINT));
        assert!(error.downcast_ref::<ProgramError>().is_some());
    }

    #[test]
    fn owned_run_refuses_tracefs_lifecycle_loss_with_actionable_remediation() {
        let mut state = ();
        let error = attach_lifecycle_with::<_, ()>(
            &mut state,
            true,
            |_, _| {
                Err(
                    aya::programs::ProgramError::IOError(io::Error::other("tracefs not found"))
                        .into(),
                )
            },
            |_, _, _| Ok(()),
        )
        .unwrap_err();
        let rendered = format!("{error:#}");

        assert!(rendered.contains("owned run"));
        assert!(rendered.contains("tracefs"));
        assert!(rendered.contains("root"));
        assert!(rendered.contains("gid="));
        assert!(rendered.contains("0750"));
        assert!(rendered.contains("tracefs not found"));
        assert!(error.downcast_ref::<ProgramError>().is_some());
    }

    #[test]
    fn non_tracefs_lifecycle_error_stays_fail_closed() {
        let mut state = ();
        let error = attach_lifecycle_with::<_, ()>(
            &mut state,
            false,
            |_, _| {
                Err(ProgramError::SyscallError(aya::sys::SyscallError {
                    call: "perf_event_open_trace_point",
                    io_error: io::Error::from_raw_os_error(libc::EPERM),
                })
                .into())
            },
            |_, _, _| Ok(()),
        )
        .unwrap_err();

        assert!(format!("{error:#}").contains("Operation not permitted"));
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
        let first = counter_snapshot_with(|index| {
            Ok(cells[index as usize]
                .iter()
                .copied()
                .fold(0u64, u64::saturating_add))
        })
        .unwrap();
        assert_eq!(first.ring_loss, 3);
        assert_eq!(first.export_state_failures, 7);
        assert_eq!(first.export_bounded_read_failures, 11);
        assert_eq!(first.loader_hits, 15);
        assert_eq!(first.loader_state_read_failures, 19);

        let mut retained = CounterSnapshot::default();
        assert!(retained.replace_with(first));
        assert_eq!(retained, first);
        let cells: [&[u64]; 5] = [&[2, 2], &[4, 4], &[6, 6], &[8, 8], &[10, 10]];
        let next = counter_snapshot_with(|index| {
            Ok(cells[index as usize]
                .iter()
                .copied()
                .fold(0u64, u64::saturating_add))
        })
        .unwrap();
        assert!(retained.replace_with(next));
        assert_eq!(
            retained.loader_hits, 16,
            "absolute values are replaced, not added"
        );

        let decreased = CounterSnapshot {
            ring_loss: next.ring_loss - 1,
            ..next
        };
        assert!(!retained.replace_with(decreased));
        assert_eq!(
            retained, next,
            "a regressing cell retains the prior authority"
        );
    }

    #[test]
    fn return_failure_suppresses_its_entry_without_blocking_another_slot() {
        let slots = [test_slot(0), test_slot(1)];
        let mut attempted = Vec::new();
        let outcome = attach_targets_with(
            &slots,
            CapturePolicy::Allowlisted,
            |program, slot| {
                attempted.push((program, slot.index));
                if program == "p11_return" && slot.index == 0 {
                    anyhow::bail!("injected return failure")
                }
                Ok(())
            },
            |_| Some(10),
        );

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
            [("p11_return", 0), ("p11_return", 1), ("p11_entry", 1),]
        );
    }

    #[test]
    fn entry_failure_records_only_the_successful_return_endpoint() {
        let outcome = attach_targets_with(
            &[test_slot(0)],
            CapturePolicy::Allowlisted,
            |program, _| {
                if program == "p11_entry" {
                    anyhow::bail!("injected entry failure")
                }
                Ok(())
            },
            |_| Some(10),
        );

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
            |program, slot| {
                events.borrow_mut().push((program, slot.index));
                Ok(())
            },
            |slot: &Slot| {
                let now = timestamp.get();
                timestamp.set(now + 10);
                events.borrow_mut().push(("completed", slot.index));
                Some(now)
            },
        );

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
            |_, _| Ok(()),
            |_| Some(10),
        );
        let mut history = initial.successful;
        assert_eq!(history.len(), 2);

        let replacement = attach_targets_with(
            &[test_slot(0)],
            CapturePolicy::Allowlisted,
            |_, _| Ok(()),
            |_| Some(20),
        );
        history.extend(replacement.successful);
        assert_eq!(
            history.len(),
            2,
            "the same slot's return/entry endpoint identities are lifetime-deduplicated"
        );

        let new_slot = attach_targets_with(
            &[test_slot(1)],
            CapturePolicy::Allowlisted,
            |_, _| Ok(()),
            |_| Some(30),
        );
        history.extend(new_slot.successful);
        assert_eq!(history.len(), 4);
    }

    #[test]
    fn terminal_detach_orders_every_static_and_dynamic_link_and_keeps_going_after_error() {
        let mut safe = Vec::new();
        detach_producers_with(CapturePolicy::Allowlisted, false, |producer| {
            safe.push(producer);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            safe,
            [
                ProducerProgram::UProbe("p11_entry"),
                ProducerProgram::UProbe("p11_return"),
            ]
        );

        let mut aggregate = Vec::new();
        detach_producers_with(CapturePolicy::AggregateOnly, false, |producer| {
            aggregate.push(producer);
            Ok(())
        })
        .unwrap();
        assert_eq!(aggregate, safe);

        let mut unsafe_cgroup = Vec::new();
        detach_producers_with(CapturePolicy::UnsafeUnvalidatedMetadata, true, |producer| {
            unsafe_cgroup.push(producer);
            Ok(())
        })
        .unwrap();
        assert_eq!(
            unsafe_cgroup,
            [
                ProducerProgram::UProbe("p11_entry"),
                ProducerProgram::UProbe("p11_entry_template"),
                ProducerProgram::UProbe("p11_entry_template_types"),
                ProducerProgram::UProbe("p11_entry_template_pair"),
                ProducerProgram::TracePoint("task_newtask"),
                ProducerProgram::UProbe("p11_return"),
            ]
        );

        let mut attempted = Vec::new();
        let error = detach_producers_with(
            CapturePolicy::UnsafeUnvalidatedMetadata,
            false,
            |producer| {
                attempted.push(producer);
                if producer == ProducerProgram::UProbe("p11_entry_template") {
                    anyhow::bail!("injected detach failure");
                }
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(error.to_string(), "injected detach failure");
        assert_eq!(
            attempted,
            [
                ProducerProgram::UProbe("p11_entry"),
                ProducerProgram::UProbe("p11_entry_template"),
                ProducerProgram::UProbe("p11_entry_template_types"),
                ProducerProgram::UProbe("p11_entry_template_pair"),
                ProducerProgram::UProbe("p11_return"),
            ]
        );

        let mut links = Vec::new();
        let errors = detach_selected_with(
            vec![
                (ProducerProgram::UProbe("p11_return"), 0),
                (ProducerProgram::UProbe("p11_entry"), 1),
                (ProducerProgram::UProbe("p11_entry"), 2),
                (ProducerProgram::UProbe("p11_return"), 3),
            ],
            |link| {
                links.push(link);
                if link == 1 {
                    anyhow::bail!("injected dynamic-link detach failure")
                }
                Ok(())
            },
        );
        assert_eq!(errors.len(), 1);
        assert_eq!(
            links,
            [1, 2, 0, 3],
            "both dynamic links are attempted after one fails"
        );
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
            ]
        );
        assert_eq!(
            FEATURE_POLICY_MAPS.map(|(name, _)| name),
            ["ATTR_BOOL_BITS"]
        );
        assert_eq!(TAIL_POLICY_MAP, "TAIL_CALLS");
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
        assert_eq!(
            entry_program(&SlotSemantics::COUNT_ONLY, CapturePolicy::Allowlisted),
            "p11_entry"
        );

        let mut template = SlotSemantics::COUNT_ONLY;
        template.template0_arg = 1;
        assert_eq!(
            entry_program(&template, CapturePolicy::UnsafeUnvalidatedMetadata),
            "p11_entry_template"
        );
        assert_eq!(
            entry_program(&template, CapturePolicy::Allowlisted),
            "p11_entry"
        );
        assert_eq!(
            entry_program(&template, CapturePolicy::AggregateOnly),
            "p11_entry"
        );

        let mut second_template = SlotSemantics::COUNT_ONLY;
        second_template.template0_arg = 2;
        second_template.template1_arg = 4;
        assert_eq!(
            entry_program(&second_template, CapturePolicy::UnsafeUnvalidatedMetadata),
            "p11_entry_template_pair"
        );

        let mut types_only = SlotSemantics::COUNT_ONLY;
        types_only.template0_arg = 2;
        types_only.semantic_flags = p11scope_ebpf_common::semantic_flags::TEMPLATE0_TYPES_ONLY;
        assert_eq!(
            entry_program(&types_only, CapturePolicy::UnsafeUnvalidatedMetadata),
            "p11_entry_template_types"
        );

        let mut async_call = SlotSemantics::COUNT_ONLY;
        async_call.async_name_arg = 1;
        assert_ne!(async_call.async_name_arg, ARG_NONE);
        assert_eq!(
            entry_program(&async_call, CapturePolicy::UnsafeUnvalidatedMetadata),
            "p11_entry"
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

        let key = pause_key_for(&Scope::Pid(42), Some(&capability))
            .unwrap()
            .unwrap();
        assert_eq!(key.tgid, 42);
        assert_eq!(key.pad, 0);
        assert_eq!(key.generation_token, 99);
        assert!(pause_key_for(&Scope::Pid(42), None).unwrap().is_none());
    }
}
