//! Loading and attaching. One selected entry uprobe + one uretprobe serve
//! each slot; the attach cookie carries the slot index.

use crate::plan::AttachPlan;
use crate::verify::VerifiedObjects;
use anyhow::{Context as _, Result, anyhow, bail};
use aya::Ebpf;
use aya::maps::{Array, HashMap, Map, MapType, ProgramArray};
use aya::programs::uprobe::{UProbeAttachLocation, UProbeAttachPoint, UProbeScope};
use aya::programs::{TracePoint, UProbe};
use p11scope_ebpf_common::{
    ARG_NONE, FLAG_POLICY_AGGREGATE, FLAG_POLICY_ALLOWLISTED,
    FLAG_POLICY_UNSAFE_UNVALIDATED_METADATA, FUNCTION_NAME_MAX_BYTES, FunctionNameKey, MAX_SLOTS,
    SlotSemantics,
};
use pkcs11_proxy_ng_types::mechanism_registry::MechanismRegistry;
use std::collections::BTreeMap;
use std::mem::{size_of, size_of_val};
use std::os::fd::{AsFd as _, AsRawFd as _};
use std::path::PathBuf;

const BASE_POLICY_MAPS: [&str; 6] = [
    "CONFIG",
    "PID_FILTER",
    "CGROUP_FILTER",
    "SLOT_SEMANTICS",
    "ASYNC_FUNCTIONS",
    "MECH_SHAPE",
];
const FEATURE_POLICY_MAPS: [&str; 1] = ["ATTR_BOOL_BITS"];
const TAIL_POLICY_MAP: &str = "TEMPLATE_TAIL";

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
            "discover" => bail!("discover does not accept --unsafe-unvalidated-metadata"),
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

pub struct Session {
    pub ebpf: Ebpf,
    attach_failures: Vec<(u32, String)>,
    attached: usize,
    policy: CapturePolicy,
    fork_attached: bool,
    _config: u64,
    _cgroup_file: Option<std::fs::File>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProducerProgram {
    UProbe(&'static str),
    TracePoint(&'static str),
}

fn detach_producers_with(
    policy: CapturePolicy,
    fork_attached: bool,
    mut detach: impl FnMut(ProducerProgram) -> Result<()>,
) -> Result<()> {
    detach(ProducerProgram::UProbe("p11_entry"))?;
    if policy.uses_unsafe_decoders() {
        for name in [
            "p11_entry_template",
            "p11_entry_template_types",
            "p11_entry_template_pair",
        ] {
            detach(ProducerProgram::UProbe(name))?;
        }
    }
    if fork_attached {
        detach(ProducerProgram::TracePoint("sched_process_fork"))?;
    }
    detach(ProducerProgram::UProbe("p11_return"))
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

fn publish_slot_semantics(ebpf: &mut Ebpf, plan: &AttachPlan) -> Result<()> {
    let mut expected = vec![SlotSemantics::COUNT_ONLY; MAX_SLOTS as usize];
    let mut seen = std::collections::BTreeSet::new();
    for slot in &plan.slots {
        if !seen.insert(slot.index) {
            bail!("attach plan repeats slot {}", slot.index);
        }
        let target = expected
            .get_mut(slot.index as usize)
            .with_context(|| format!("slot {} exceeds SLOT_SEMANTICS capacity", slot.index))?;
        if let Some(index) = slot.semantics.argument_indices().find(|index| *index > 6) {
            bail!(
                "slot {} requests forbidden argument index {index}",
                slot.index
            );
        }
        *target = slot.semantics;
    }

    let info = policy_map_data(
        "SLOT_SEMANTICS",
        ebpf.map("SLOT_SEMANTICS").context("SLOT_SEMANTICS map")?,
    )?
    .info()
    .context("reading SLOT_SEMANTICS map info")?;
    if info.map_type()? != MapType::Array || info.max_entries() != MAX_SLOTS {
        bail!(
            "SLOT_SEMANTICS has type {:?} and capacity {}, expected Array and {}",
            info.map_type()?,
            info.max_entries(),
            MAX_SLOTS
        );
    }
    let mut semantics: Array<_, SlotSemantics> = Array::try_from(
        ebpf.map_mut("SLOT_SEMANTICS")
            .context("SLOT_SEMANTICS map")?,
    )?;
    for (index, value) in expected.iter().copied().enumerate() {
        semantics.set(index as u32, value, 0)?;
    }
    let semantics: Array<_, SlotSemantics> =
        Array::try_from(ebpf.map("SLOT_SEMANTICS").context("SLOT_SEMANTICS map")?)?;
    let actual = semantics.iter().collect::<Result<Vec<_>, _>>()?;
    if actual != expected {
        bail!("SLOT_SEMANTICS exact readback differs from the attach plan");
    }
    Ok(())
}

fn publish_async_catalog(ebpf: &mut Ebpf) -> Result<()> {
    let expected = standard_async_catalog()?;

    let info = policy_map_data(
        "ASYNC_FUNCTIONS",
        ebpf.map("ASYNC_FUNCTIONS").context("ASYNC_FUNCTIONS map")?,
    )?
    .info()
    .context("reading ASYNC_FUNCTIONS map info")?;
    if info.map_type()? != MapType::Hash
        || info.max_entries() != 128
        || info.key_size() != size_of::<FunctionNameKey>() as u32
    {
        bail!(
            "ASYNC_FUNCTIONS has type {:?}, key size {}, and capacity {}, expected Hash, 32, and 128",
            info.map_type()?,
            info.key_size(),
            info.max_entries()
        );
    }
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
    let Some(map) = ebpf.map("ATTR_BOOL_BITS") else {
        if enabled {
            bail!("ATTR_BOOL_BITS is missing from the diagnostic eBPF object");
        }
        return Ok(());
    };
    let info = policy_map_data("ATTR_BOOL_BITS", map)?
        .info()
        .context("reading ATTR_BOOL_BITS map info")?;
    if info.map_type()? != MapType::Hash || info.max_entries() != 16 {
        bail!(
            "ATTR_BOOL_BITS has type {:?} and capacity {}, expected Hash and 16",
            info.map_type()?,
            info.max_entries()
        );
    }
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
    for name in BASE_POLICY_MAPS {
        freeze_map(name, ebpf.map(name).with_context(|| format!("{name} map"))?)?;
    }
    for name in FEATURE_POLICY_MAPS {
        if let Some(map) = ebpf.map(name) {
            freeze_map(name, map)?;
        }
    }
    Ok(())
}

fn publish_and_freeze_template_tail(ebpf: &mut Ebpf, enabled: bool) -> Result<()> {
    if ebpf.map(TAIL_POLICY_MAP).is_none() {
        if enabled {
            bail!("{TAIL_POLICY_MAP} is missing from the diagnostic eBPF object");
        }
        return Ok(());
    }
    let info = policy_map_data(
        TAIL_POLICY_MAP,
        ebpf.map(TAIL_POLICY_MAP).context("TEMPLATE_TAIL map")?,
    )?
    .info()
    .context("reading TEMPLATE_TAIL map info")?;
    if info.map_type()? != MapType::ProgramArray || info.max_entries() != 1 {
        bail!(
            "TEMPLATE_TAIL has type {:?} and capacity {}, expected ProgramArray and 1",
            info.map_type()?,
            info.max_entries()
        );
    }

    if enabled {
        let (tail_fd, expected_id) = {
            let tail: &UProbe = ebpf
                .program("p11_entry_template_second")
                .context("program p11_entry_template_second missing from object")?
                .try_into()?;
            (tail.fd()?.try_clone()?, tail.info()?.id())
        };
        let mut tails: ProgramArray<_> =
            ProgramArray::try_from(ebpf.map_mut(TAIL_POLICY_MAP).context("TEMPLATE_TAIL map")?)?;
        tails.set(0, &tail_fd, 0)?;
        let actual_id = program_array_id(
            TAIL_POLICY_MAP,
            ebpf.map(TAIL_POLICY_MAP).context("TEMPLATE_TAIL map")?,
            0,
        )?;
        if actual_id != Some(expected_id) {
            bail!(
                "TEMPLATE_TAIL exact readback id {actual_id:?} differs from loaded program {expected_id}"
            );
        }
    } else if let Some(id) = program_array_id(
        TAIL_POLICY_MAP,
        ebpf.map(TAIL_POLICY_MAP).context("TEMPLATE_TAIL map")?,
        0,
    )? {
        bail!("TEMPLATE_TAIL unexpectedly contains program id {id} for the selected policy");
    }
    freeze_map(
        TAIL_POLICY_MAP,
        ebpf.map(TAIL_POLICY_MAP).context("TEMPLATE_TAIL map")?,
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
const UNSUPPORTED_ENV_HINT: &str = "hint: this usually means the environment cannot load or \
attach BPF programs at all — missing CAP_BPF and/or CAP_SYS_ADMIN (or root), a kernel \
lockdown mode, a kernel below the supported floor (>= 5.15), missing BTF \
(/sys/kernel/btf/vmlinux), or a restrictive kernel.perf_event_paranoid sysctl. See \
docs/notes/phase5-unsupported.md for what each looks like when observed.";

impl Session {
    pub fn start(
        plan: &AttachPlan,
        scope: &Scope,
        objects: &VerifiedObjects,
        policy: CapturePolicy,
    ) -> Result<Self> {
        objects
            .ensure_stable()
            .map_err(anyhow::Error::msg)
            .context("checking authorized provider objects before attach")?;
        let session = Self::start_inner(plan, scope, objects, policy)
            .map_err(|e| anyhow!("{e:#}\n{UNSUPPORTED_ENV_HINT}"))?;
        objects
            .ensure_stable()
            .map_err(anyhow::Error::msg)
            .context("checking authorized provider objects after attach")?;
        Ok(session)
    }

    fn start_inner(
        plan: &AttachPlan,
        scope: &Scope,
        objects: &VerifiedObjects,
        policy: CapturePolicy,
    ) -> Result<Self> {
        if policy.uses_unsafe_decoders() && !cfg!(feature = "unsafe-unvalidated-metadata") {
            bail!("unsafe-unvalidated-metadata policy is absent from this eBPF object");
        }
        let mut ebpf = Ebpf::load(crate::EBPF_OBJECT).context("loading BPF object")?;
        let published_scope = crate::scope::publish(&mut ebpf, scope, policy)
            .context("publishing scope and capture policy")?;
        publish_slot_semantics(&mut ebpf, plan).context("publishing SLOT_SEMANTICS")?;
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
        let unsafe_enabled =
            cfg!(feature = "unsafe-unvalidated-metadata") && policy.uses_unsafe_decoders();
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

        let mut attach_failures = Vec::new();
        let mut attached = 0usize;
        let attach_paths: Vec<PathBuf> = plan
            .slots
            .iter()
            .map(|slot| {
                objects
                    .attach_path(&slot.object)
                    .map_err(anyhow::Error::msg)
            })
            .collect::<Result<_>>()?;

        let programs: &[&str] = if unsafe_enabled {
            &[
                "p11_return",
                "p11_entry",
                "p11_entry_template",
                "p11_entry_template_types",
                "p11_entry_template_pair",
                "p11_entry_template_second",
            ]
        } else {
            &["p11_return", "p11_entry"]
        };
        for prog_name in programs {
            let prog: &mut UProbe = ebpf
                .program_mut(prog_name)
                .with_context(|| format!("program {prog_name} missing from object"))?
                .try_into()?;
            prog.load()
                .with_context(|| format!("loading {prog_name}"))?;
        }
        publish_and_freeze_template_tail(&mut ebpf, unsafe_enabled)
            .context("publishing and freezing TEMPLATE_TAIL")?;

        let fork_attached = matches!(scope, Scope::Cgroup { .. }) && policy.uses_events();
        if fork_attached {
            let fork: &mut TracePoint = ebpf
                .program_mut("sched_process_fork")
                .context("program sched_process_fork missing from object")?
                .try_into()?;
            fork.load().context("loading sched_process_fork")?;
            fork.attach("sched", "sched_process_fork")
                .context("attaching sched_process_fork")?;
        }

        let mut return_attached = vec![false; plan.slots.len()];
        {
            let prog: &mut UProbe = ebpf.program_mut("p11_return").unwrap().try_into()?;
            for (position, slot) in plan.slots.iter().enumerate() {
                let point = UProbeAttachPoint {
                    location: UProbeAttachLocation::AbsoluteOffset(slot.file_offset),
                    cookie: Some(slot.index as u64),
                };
                match prog.attach(point, &attach_paths[position], uprobe_scope) {
                    Ok(_) => {
                        attached += 1;
                        return_attached[position] = true;
                    }
                    Err(e) => attach_failures.push((
                        slot.index,
                        format!(
                            "p11_return at {}+{:#x}: {}",
                            slot.object,
                            slot.file_offset,
                            error_chain(&e)
                        ),
                    )),
                }
            }
        }
        let entry_programs: &[&str] = if unsafe_enabled {
            &[
                "p11_entry",
                "p11_entry_template",
                "p11_entry_template_types",
                "p11_entry_template_pair",
            ]
        } else {
            &["p11_entry"]
        };
        for prog_name in entry_programs {
            let prog: &mut UProbe = ebpf.program_mut(prog_name).unwrap().try_into()?;
            for (position, slot) in plan.slots.iter().enumerate() {
                if !return_attached[position]
                    || entry_program(&slot.semantics, policy) != *prog_name
                {
                    continue;
                }
                let point = UProbeAttachPoint {
                    location: UProbeAttachLocation::AbsoluteOffset(slot.file_offset),
                    cookie: Some(slot.index as u64),
                };
                match prog.attach(point, &attach_paths[position], uprobe_scope) {
                    Ok(_) => attached += 1,
                    Err(e) => attach_failures.push((
                        slot.index,
                        format!(
                            "{prog_name} at {}+{:#x}: {}",
                            slot.object,
                            slot.file_offset,
                            error_chain(&e)
                        ),
                    )),
                }
            }
        }

        Ok(Self {
            ebpf,
            attach_failures,
            attached,
            policy,
            fork_attached,
            _config: published_scope.config,
            _cgroup_file: published_scope.cgroup_file,
        })
    }

    /// Detach every event/map producer while keeping the maps and ring reader
    /// available for a best-effort terminal drain and snapshot. Entry probes
    /// go first so fewer calls are stranded before the return probes are
    /// removed last. Kernel detach does not wait for callbacks already running
    /// on another CPU; callers must not claim that the terminal drain is final.
    pub fn detach_producers(&mut self) -> Result<()> {
        let ebpf = &mut self.ebpf;
        detach_producers_with(self.policy, self.fork_attached, |producer| {
            match producer {
                ProducerProgram::UProbe(name) => {
                    let program: &mut UProbe = ebpf
                        .program_mut(name)
                        .with_context(|| format!("program {name} missing during detach"))?
                        .try_into()?;
                    program
                        .unload()
                        .with_context(|| format!("detaching {name}"))?;
                }
                ProducerProgram::TracePoint(name) => {
                    let program: &mut TracePoint = ebpf
                        .program_mut(name)
                        .with_context(|| format!("program {name} missing during detach"))?
                        .try_into()?;
                    program
                        .unload()
                        .with_context(|| format!("detaching {name}"))?;
                }
            }
            Ok(())
        })
    }

    /// Attach points that failed — reported as an evidence gap, never
    /// silently treated as zero calls.
    pub fn attach_failures(&self) -> &[(u32, String)] {
        &self.attach_failures
    }

    /// Successful attachments across both programs (2 per fully-attached slot).
    pub fn attached_probes(&self) -> usize {
        self.attached
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
    use p11scope_ebpf_common::{ARG_NONE, SlotSemantics};

    #[test]
    fn terminal_detach_orders_selected_producers_and_stops_on_error() {
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
                ProducerProgram::TracePoint("sched_process_fork"),
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
            ]
        );
    }

    #[test]
    fn immutable_map_inventory_covers_every_authorization_input() {
        assert_eq!(
            BASE_POLICY_MAPS,
            [
                "CONFIG",
                "PID_FILTER",
                "CGROUP_FILTER",
                "SLOT_SEMANTICS",
                "ASYNC_FUNCTIONS",
                "MECH_SHAPE",
            ]
        );
        assert_eq!(FEATURE_POLICY_MAPS, ["ATTR_BOOL_BITS"]);
        assert_eq!(TAIL_POLICY_MAP, "TEMPLATE_TAIL");
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
            program_array_lookup_result("TEMPLATE_TAIL", 0, 37, Ok(())).unwrap(),
            Some(37)
        );
        assert_eq!(
            program_array_lookup_result(
                "TEMPLATE_TAIL",
                0,
                0,
                Err(std::io::Error::from_raw_os_error(libc::ENOENT)),
            )
            .unwrap(),
            None
        );

        let error = program_array_lookup_result(
            "TEMPLATE_TAIL",
            0,
            0,
            Err(std::io::Error::from_raw_os_error(libc::EPERM)),
        )
        .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(rendered.contains("reading back TEMPLATE_TAIL[0]"));
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
}
