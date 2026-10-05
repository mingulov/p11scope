//! SPDX-License-Identifier: GPL-3.0-or-later
//! Preparation-only capability for the dedicated compact Inventory object.
use super::{
    AttachBackend, BPF_F_RDONLY_PROG, ExactMapMetadata, Scope, compare_map_metadata, freeze_map,
    map_metadata, publish_and_freeze_tail_calls, read_map_metadata, require_empty_stack_guard,
};
use crate::capacity::{CallerBudget, InventoryBudget};
use crate::events::DiscoveryDomain;
use crate::process::PidPin;
use anyhow::{Context as _, Result, bail, ensure};
use aya::maps::{Array, Map, MapData, MapType};
use aya::programs::{ProbeKind, Program, RawTracePoint, UProbe};
use aya::{Btf, Ebpf, EbpfLoader};
#[cfg(not(p11scope_small_discovery_ring))]
use p11scope_ebpf_common::INVENTORY_DISCOVERY_BYTES;
use p11scope_ebpf_common::{
    IMAGE_IDENTITY_TICKET_LIMIT, INVENTORY_OWNER_LIMIT, INVENTORY_USAGE_VERSION,
    ImageIdentityControl, InventoryUsageConfig, ThreadOwnerControl,
};
use std::collections::BTreeMap;
use std::num::NonZeroU32;

/// No links, event domain, or mutable object access exist on this capability.
/// Private activation consumes it before installing any producers.
pub(crate) struct PreparedInventory {
    ebpf: Ebpf,
    discovery_domain: DiscoveryDomain,
    budget: InventoryBudget,
    flavor: InventoryFlavor,
    capacity: NonZeroU32,
    backend: AttachBackend,
    scope: Scope,
    pid_pin: Option<PidPin>,
}

#[derive(Clone, Copy)]
enum InventoryFlavor {
    Global,
    Callers(CallerBudget),
}

impl PreparedInventory {
    pub(crate) fn prepare(
        scope: Scope,
        budget: InventoryBudget,
        backend: AttachBackend,
    ) -> Result<Self> {
        Self::prepare_inner(
            scope,
            budget,
            backend,
            #[cfg(test)]
            |_, _| Ok(()),
        )
    }

    pub(crate) fn prepare_callers(
        scope: Scope,
        endpoint_budget: InventoryBudget,
        caller_budget: CallerBudget,
        backend: AttachBackend,
    ) -> Result<Self> {
        Self::prepare_inner_flavor(
            scope,
            None,
            endpoint_budget,
            backend,
            InventoryFlavor::Callers(caller_budget),
            #[cfg(test)]
            |_, _| Ok(()),
        )
    }

    /// The capture facade's caller preparation: PID scope keeps the custody
    /// the facade already opened and checked, instead of opening another.
    pub(crate) fn prepare_callers_pinned(
        scope: Scope,
        pin: Option<PidPin>,
        endpoint_budget: InventoryBudget,
        caller_budget: CallerBudget,
        backend: AttachBackend,
    ) -> Result<Self> {
        Self::prepare_inner_flavor(
            scope,
            pin,
            endpoint_budget,
            backend,
            InventoryFlavor::Callers(caller_budget),
            #[cfg(test)]
            |_, _| Ok(()),
        )
    }

    pub(crate) fn endpoint_capacity(&self) -> NonZeroU32 {
        self.capacity
    }

    pub(crate) fn budget(&self) -> InventoryBudget {
        self.budget
    }

    fn prepare_inner(
        scope: Scope,
        budget: InventoryBudget,
        backend: AttachBackend,
        #[cfg(test)] observe: impl FnMut(&PreparingInventory, InventoryPreparation) -> Result<()>,
    ) -> Result<Self> {
        Self::prepare_inner_flavor(
            scope,
            None,
            budget,
            backend,
            InventoryFlavor::Global,
            #[cfg(test)]
            observe,
        )
    }

    fn prepare_inner_flavor(
        scope: Scope,
        pinned: Option<PidPin>,
        budget: InventoryBudget,
        backend: AttachBackend,
        flavor: InventoryFlavor,
        #[cfg(test)] mut observe: impl FnMut(&PreparingInventory, InventoryPreparation) -> Result<()>,
    ) -> Result<Self> {
        let capacity = inventory_capacity(budget)?;
        if let InventoryFlavor::Callers(caller_budget) = flavor {
            ensure!(
                budget == caller_budget.endpoint_budget(),
                "caller endpoint budget differs from Inventory budget"
            );
        }
        let pid_pin = match (&scope, pinned) {
            (Scope::Pid(pid), pinned) => {
                NonZeroU32::new(*pid).context("Inventory PID must be non-zero")?;
                match pinned {
                    Some(pin) => {
                        ensure!(
                            pin.pid() == *pid,
                            "Inventory PID custody names pid {} instead of {pid}",
                            pin.pid()
                        );
                        Some(pin)
                    }
                    None => Some(PidPin::open(*pid).map_err(anyhow::Error::msg)?),
                }
            }
            (Scope::Cgroup { .. } | Scope::System, None) => None,
            (Scope::Cgroup { .. } | Scope::System, Some(_)) => {
                bail!("Inventory PID custody supplied for a non-PID scope")
            }
        };
        let btf = Btf::from_sys_fs().context("loading required vmlinux BTF for Inventory")?;
        let state = PreparingInventory {
            ebpf: None,
            discovery_domain: None,
        };
        let execute = |state: &mut PreparingInventory, step| {
            match step {
                InventoryPreparation::LoadObject => {
                    // Fresh maps only. This allocation capacity is immutable
                    // and is not a policy for growing or renewing sessions.
                    let mut loader = EbpfLoader::new();
                    loader
                        .btf(Some(&btf))
                        .allow_unsupported_maps()
                        .map_max_entries("USAGE", capacity.get());
                    let bytes = match flavor {
                        InventoryFlavor::Global => crate::EBPF_INVENTORY_OBJECT,
                        InventoryFlavor::Callers(caller_budget) => {
                            loader
                                .map_max_entries("ENDPOINT_OBJECT", capacity.get())
                                .map_max_entries(
                                    "CALLER_USE",
                                    callers::caller_use_capacity(caller_budget)?,
                                );
                            crate::EBPF_INVENTORY_CALLERS_OBJECT
                        }
                    };
                    state.ebpf = Some(
                        loader
                            .load(bytes)
                            .context("loading fresh Inventory object with exact capacity")?,
                    );
                }
                InventoryPreparation::ValidateMaps => match flavor {
                    InventoryFlavor::Global => {
                        validate_runtime_inventory_maps(state.ebpf()?, capacity)?
                    }
                    InventoryFlavor::Callers(caller_budget) => {
                        callers::validate_runtime_caller_maps(state.ebpf()?, caller_budget)?
                    }
                },
                InventoryPreparation::ValidatePrograms => {
                    validate_runtime_inventory_programs(state.ebpf()?)?;
                }
                InventoryPreparation::PublishScope => {
                    crate::scope::publish_inventory(state.ebpf_mut()?, &scope)?;
                }
                InventoryPreparation::WriteUsageConfig => {
                    let mut map: Array<_, InventoryUsageConfig> = Array::try_from(
                        state
                            .ebpf_mut()?
                            .map_mut("USAGE_CONFIG")
                            .context("USAGE_CONFIG map")?,
                    )?;
                    map.set(
                        0,
                        InventoryUsageConfig {
                            version: INVENTORY_USAGE_VERSION,
                            endpoint_capacity: capacity.get(),
                        },
                        0,
                    )?;
                }
                InventoryPreparation::ReadUsageConfig => {
                    let ebpf = state.ebpf()?;
                    let map: Array<_, InventoryUsageConfig> =
                        Array::try_from(ebpf.map("USAGE_CONFIG").context("USAGE_CONFIG map")?)?;
                    let (_, usage) =
                        inventory_map_data("USAGE", ebpf.map("USAGE").context("USAGE map")?)?;
                    validate_inventory_usage_config(
                        capacity,
                        read_map_metadata("USAGE", usage)?.max_entries,
                        map.get(&0, 0)?,
                    )?;
                }
                InventoryPreparation::WriteOwner => {
                    let mut map: Array<_, ThreadOwnerControl> = Array::try_from(
                        state
                            .ebpf_mut()?
                            .map_mut("OWNER_CTL")
                            .context("OWNER_CTL map")?,
                    )?;
                    map.set(
                        0,
                        ThreadOwnerControl {
                            limit: INVENTORY_OWNER_LIMIT,
                            ..ThreadOwnerControl::default()
                        },
                        0,
                    )?;
                }
                InventoryPreparation::ReadOwner => {
                    let map: Array<_, ThreadOwnerControl> =
                        Array::try_from(state.ebpf()?.map("OWNER_CTL").context("OWNER_CTL map")?)?;
                    validate_inventory_owner_control(map.get(&0, 0)?)?;
                }
                InventoryPreparation::WriteCallerControl => {
                    let mut map: Array<_, ImageIdentityControl> = Array::try_from(
                        state
                            .ebpf_mut()?
                            .map_mut("COOKIE_CTL")
                            .context("COOKIE_CTL map")?,
                    )?;
                    map.set(
                        0,
                        ImageIdentityControl {
                            limit: IMAGE_IDENTITY_TICKET_LIMIT,
                            ..Default::default()
                        },
                        0,
                    )?;
                }
                InventoryPreparation::ReadCallerControl => {
                    let map: Array<_, ImageIdentityControl> = Array::try_from(
                        state.ebpf()?.map("COOKIE_CTL").context("COOKIE_CTL map")?,
                    )?;
                    callers::validate_caller_control(map.get(&0, 0)?)?;
                }
                InventoryPreparation::Freeze(name) => {
                    let map = state
                        .ebpf()?
                        .map(name)
                        .with_context(|| format!("{name} map"))?;
                    if name == "STACK_GUARD" {
                        require_empty_stack_guard(map)?;
                    }
                    freeze_map(name, map)?;
                }
                InventoryPreparation::LoadProgram(name, mode) => {
                    let program = state
                        .ebpf_mut()?
                        .program_mut(name)
                        .with_context(|| format!("Inventory program {name}"))?;
                    match mode {
                        InventoryProgramLoad::RawTracePoint => {
                            let program: &mut RawTracePoint = program.try_into()?;
                            program.load()?;
                        }
                        InventoryProgramLoad::UProbe | InventoryProgramLoad::UProbeMulti => {
                            let program: &mut UProbe = program.try_into()?;
                            if mode == InventoryProgramLoad::UProbeMulti {
                                program.load_multi()?;
                            } else {
                                program.load()?;
                            }
                        }
                    }
                }
                InventoryPreparation::PublishTailCalls => {
                    publish_and_freeze_tail_calls(state.ebpf_mut()?, false)?;
                }
                InventoryPreparation::RetainDiscovery => {
                    state.discovery_domain = Some(DiscoveryDomain::from_discovery(state.ebpf()?)?);
                }
                InventoryPreparation::RecheckCustody => {
                    if let Some(pin) = &pid_pin {
                        require_inventory_custody_with(|| {
                            pin.original_exited()
                                .map(|exited| !exited)
                                .map_err(anyhow::Error::msg)
                        })?;
                    }
                }
            }
            #[cfg(test)]
            observe(state, step)?;
            Ok(())
        };
        let mut prepared = match flavor {
            InventoryFlavor::Global => prepare_inventory_with(backend, state, execute)?,
            InventoryFlavor::Callers(caller_budget) => callers::prepare_caller_inventory_with(
                budget,
                caller_budget,
                backend,
                state,
                execute,
            )?,
        };
        Ok(Self {
            ebpf: prepared
                .ebpf
                .take()
                .context("Inventory preparation omitted object")?,
            discovery_domain: prepared
                .discovery_domain
                .take()
                .context("Inventory preparation omitted retained DISCOVERY")?,
            budget,
            flavor,
            capacity,
            backend,
            scope,
            pid_pin,
        })
    }
}

// A failed transaction drops both the fresh object and any acquired domain.
// These temporary Options never weaken the returned capability's invariants.
struct PreparingInventory {
    ebpf: Option<Ebpf>,
    discovery_domain: Option<DiscoveryDomain>,
}
impl PreparingInventory {
    fn ebpf(&self) -> Result<&Ebpf> {
        self.ebpf
            .as_ref()
            .context("Inventory object has not been loaded")
    }
    fn ebpf_mut(&mut self) -> Result<&mut Ebpf> {
        self.ebpf
            .as_mut()
            .context("Inventory object has not been loaded")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InventoryMapKind {
    Array,
    Hash,
    CgroupArray,
    ProgramArray,
    PerCpuArray,
    RingBuf,
    Unsupported,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InventoryProgramKind {
    Entry,
    Return,
    RawTracePoint,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InventoryProgramLoad {
    UProbe,
    UProbeMulti,
    RawTracePoint,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InventoryPreparation {
    LoadObject,
    ValidateMaps,
    ValidatePrograms,
    PublishScope,
    WriteUsageConfig,
    ReadUsageConfig,
    WriteOwner,
    ReadOwner,
    WriteCallerControl,
    ReadCallerControl,
    Freeze(&'static str),
    LoadProgram(&'static str, InventoryProgramLoad),
    PublishTailCalls,
    RetainDiscovery,
    RecheckCustody,
}

/// The DISCOVERY size this build's Inventory objects compiled with: the
/// shared 2 MiB constant, or 4 KiB when `P11SCOPE_SMALL_DISCOVERY_RING=1`
/// built them (the host dependency never carries that feature, so the
/// small size is mirrored here from the build script's cfg). Both the
/// exact-map validator and the lifecycle high-water share pin it.
#[cfg(not(p11scope_small_discovery_ring))]
pub(crate) const EXPECTED_INVENTORY_DISCOVERY_BYTES: u32 = INVENTORY_DISCOVERY_BYTES;
#[cfg(p11scope_small_discovery_ring)]
pub(crate) const EXPECTED_INVENTORY_DISCOVERY_BYTES: u32 = 4_096;

fn inventory_capacity(budget: InventoryBudget) -> Result<NonZeroU32> {
    let n =
        u32::try_from(budget.endpoint_limit()).context("Inventory budget exceeds u32 capacity")?;
    let n = NonZeroU32::new(n).context("Inventory budget capacity must be non-zero")?;
    if budget.payload_bytes() != u64::from(n.get()) * 8 {
        bail!("Inventory payload budget disagrees with its endpoint capacity");
    }
    Ok(n)
}

fn inventory_maps(
    capacity: NonZeroU32,
) -> BTreeMap<&'static str, (InventoryMapKind, ExactMapMetadata)> {
    use InventoryMapKind as K;
    [
        (
            "CONFIG",
            K::Array,
            map_metadata(MapType::Array, 4, 8, 2, BPF_F_RDONLY_PROG),
        ),
        (
            "PID_FILTER",
            K::Hash,
            map_metadata(MapType::Hash, 4, 8, 1024, BPF_F_RDONLY_PROG),
        ),
        (
            "CGROUP_FILTER",
            K::CgroupArray,
            map_metadata(MapType::CgroupArray, 4, 4, 1, 0),
        ),
        (
            "TAIL_CALLS",
            K::ProgramArray,
            map_metadata(MapType::ProgramArray, 4, 4, 2, 0),
        ),
        // The usage entries' kernel-stack opt-out; never populated, frozen
        // empty before any load (they load for uprobe-multi under multi).
        (
            "STACK_GUARD",
            K::ProgramArray,
            map_metadata(MapType::ProgramArray, 4, 4, 1, 0),
        ),
        (
            "EVIDENCE",
            K::PerCpuArray,
            map_metadata(MapType::PerCpuArray, 4, 8, 9, 0),
        ),
        (
            "COUNTERS",
            K::PerCpuArray,
            map_metadata(MapType::PerCpuArray, 4, 8, 5, 0),
        ),
        (
            "DISCOVERY",
            K::RingBuf,
            map_metadata(
                MapType::RingBuf,
                0,
                0,
                EXPECTED_INVENTORY_DISCOVERY_BYTES,
                0,
            ),
        ),
        (
            "DISCOVERY_STATE",
            K::Hash,
            map_metadata(MapType::Hash, 24, 24, 64, 0),
        ),
        (
            "THREAD_OWNER",
            K::Unsupported,
            map_metadata(MapType::TaskStorage, 4, 544, 0, 1),
        ),
        (
            "OWNER_CTL",
            K::Array,
            map_metadata(MapType::Array, 4, 56, 1, 0),
        ),
        (
            "USAGE",
            K::Array,
            map_metadata(MapType::Array, 4, 8, capacity.get(), 0),
        ),
        (
            "USAGE_CONFIG",
            K::Array,
            map_metadata(MapType::Array, 4, 8, 1, BPF_F_RDONLY_PROG),
        ),
        (
            "USAGE_EVIDENCE",
            K::PerCpuArray,
            map_metadata(MapType::PerCpuArray, 4, 8, 3, 0),
        ),
    ]
    .into_iter()
    .map(|(name, kind, meta)| (name, (kind, meta)))
    .collect()
}

fn validate_inventory_maps(
    actual: &BTreeMap<String, (InventoryMapKind, ExactMapMetadata)>,
    capacity: NonZeroU32,
) -> Result<()> {
    let expected = inventory_maps(capacity);
    if !actual
        .keys()
        .map(String::as_str)
        .eq(expected.keys().copied())
    {
        bail!(
            "Inventory map names {:?} differ from {:?}",
            actual.keys(),
            expected.keys()
        );
    }
    for (name, (kind, metadata)) in expected {
        let (actual_kind, actual_metadata) = actual[name];
        if actual_kind != kind {
            bail!("Inventory {name} map variant {actual_kind:?} differs from {kind:?}");
        }
        compare_map_metadata(name, actual_metadata, metadata)?;
    }
    Ok(())
}

fn inventory_map_data<'a>(name: &str, map: &'a Map) -> Result<(InventoryMapKind, &'a MapData)> {
    use InventoryMapKind as K;
    match map {
        Map::Array(data) => Ok((K::Array, data)),
        Map::HashMap(data) => Ok((K::Hash, data)),
        Map::CgroupArray(data) => Ok((K::CgroupArray, data)),
        Map::ProgramArray(data) => Ok((K::ProgramArray, data)),
        Map::PerCpuArray(data) => Ok((K::PerCpuArray, data)),
        Map::RingBuf(data) => Ok((K::RingBuf, data)),
        Map::Unsupported(data) if matches!(name, "THREAD_OWNER" | "TASK_COOKIE") => {
            Ok((K::Unsupported, data))
        }
        other => bail!("Inventory refuses {name} map variant {other:?}"),
    }
}

fn validate_runtime_inventory_maps(ebpf: &Ebpf, capacity: NonZeroU32) -> Result<()> {
    let actual = ebpf
        .maps()
        .map(|(name, map)| {
            let (kind, data) = inventory_map_data(name, map)?;
            Ok((name.to_string(), (kind, read_map_metadata(name, data)?)))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    validate_inventory_maps(&actual, capacity)
}

const INVENTORY_PROGRAMS: [(&str, InventoryProgramKind); 12] = {
    use InventoryProgramKind::*;
    [
        ("dl_debug_state", Entry),
        ("function_list_entry", Entry),
        ("function_list_return", Return),
        ("interface_entry", Entry),
        ("interface_list_entry", Entry),
        ("interface_list_return", Return),
        ("interface_list_worker", Return),
        ("interface_return", Return),
        ("p11_usage_entry_ia32", Entry),
        ("p11_usage_entry_lp64", Entry),
        ("sched_process_exec", RawTracePoint),
        ("sched_process_exit", RawTracePoint),
    ]
};

fn validate_inventory_programs(actual: &BTreeMap<String, InventoryProgramKind>) -> Result<()> {
    let expected: BTreeMap<_, _> = INVENTORY_PROGRAMS
        .into_iter()
        .map(|(name, kind)| (name.to_string(), kind))
        .collect();
    if *actual != expected {
        bail!("Inventory program names/kinds {actual:?} differ from {expected:?}");
    }
    Ok(())
}

fn validate_runtime_inventory_programs(ebpf: &Ebpf) -> Result<()> {
    let actual = ebpf
        .programs()
        .map(|(name, program)| {
            let kind = match program {
                Program::UProbe(probe) => match probe.kind() {
                    ProbeKind::Entry => InventoryProgramKind::Entry,
                    ProbeKind::Return => InventoryProgramKind::Return,
                },
                Program::RawTracePoint(_) => InventoryProgramKind::RawTracePoint,
                _ => bail!("Inventory refuses program {name} with a non-Inventory kind"),
            };
            Ok((name.to_string(), kind))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    validate_inventory_programs(&actual)
}

fn inventory_program_load(name: &str, backend: AttachBackend) -> Result<InventoryProgramLoad> {
    let kind = INVENTORY_PROGRAMS
        .iter()
        .find(|(candidate, _)| *candidate == name)
        .map(|(_, kind)| *kind)
        .with_context(|| format!("unknown Inventory program {name}"))?;
    Ok(match kind {
        InventoryProgramKind::RawTracePoint => InventoryProgramLoad::RawTracePoint,
        InventoryProgramKind::Entry
            if backend == AttachBackend::Multi
                && matches!(name, "p11_usage_entry_lp64" | "p11_usage_entry_ia32") =>
        {
            InventoryProgramLoad::UProbeMulti
        }
        InventoryProgramKind::Entry | InventoryProgramKind::Return => InventoryProgramLoad::UProbe,
    })
}

fn validate_inventory_usage_config(
    capacity: NonZeroU32,
    actual: u32,
    config: InventoryUsageConfig,
) -> Result<()> {
    if !config.is_valid() || config.endpoint_capacity != capacity.get() || actual != capacity.get()
    {
        bail!(
            "USAGE_CONFIG {config:?}, USAGE capacity {actual}, and Inventory budget {} disagree",
            capacity.get()
        );
    }
    Ok(())
}

fn validate_inventory_owner_control(control: ThreadOwnerControl) -> Result<()> {
    if [
        control.limit,
        control.outstanding,
        control.poison,
        control.admission_failures,
        control.reclamation_failures,
        control.abandoned_start,
        control.abandoned_discovery,
    ] != [INVENTORY_OWNER_LIMIT, 0, 0, 0, 0, 0, 0]
    {
        bail!("OWNER_CTL exact Inventory readback differs: {control:?}");
    }
    Ok(())
}

fn prepare_inventory_with<T>(
    backend: AttachBackend,
    state: T,
    operation: impl FnMut(&mut T, InventoryPreparation) -> Result<()>,
) -> Result<T> {
    prepare_inventory_with_kind(backend, state, false, operation)
}

fn prepare_inventory_with_kind<T>(
    backend: AttachBackend,
    mut state: T,
    caller: bool,
    mut operation: impl FnMut(&mut T, InventoryPreparation) -> Result<()>,
) -> Result<T> {
    use InventoryPreparation::*;
    let initial = [
        LoadObject,
        ValidateMaps,
        ValidatePrograms,
        PublishScope,
        WriteUsageConfig,
        ReadUsageConfig,
        WriteOwner,
        ReadOwner,
        Freeze("PID_FILTER"),
        Freeze("CGROUP_FILTER"),
        Freeze("USAGE_CONFIG"),
        Freeze("THREAD_OWNER"),
        Freeze("OWNER_CTL"),
        Freeze("USAGE"),
        Freeze("STACK_GUARD"),
    ];
    for step in initial {
        operation(&mut state, step).with_context(|| format!("preparing Inventory: {step:?}"))?;
    }
    if caller {
        for step in [
            WriteCallerControl,
            ReadCallerControl,
            Freeze("TASK_COOKIE"),
            Freeze("COOKIE_CTL"),
            Freeze("CALLER_USE"),
        ] {
            operation(&mut state, step)
                .with_context(|| format!("preparing caller Inventory: {step:?}"))?;
        }
    }
    for (name, _) in INVENTORY_PROGRAMS {
        let step = LoadProgram(name, inventory_program_load(name, backend)?);
        operation(&mut state, step).with_context(|| format!("preparing Inventory: {step:?}"))?;
    }
    for step in [
        Freeze("CONFIG"),
        PublishTailCalls,
        RetainDiscovery,
        RecheckCustody,
    ] {
        operation(&mut state, step).with_context(|| format!("preparing Inventory: {step:?}"))?;
    }
    Ok(state)
}

fn require_inventory_custody_with(check: impl FnOnce() -> Result<bool>) -> Result<()> {
    if !check().context("rechecking Inventory PID custody")? {
        bail!("Inventory PID custody became stale before preparation completed");
    }
    Ok(())
}

#[cfg(test)]
mod privileged_tests;
#[cfg(test)]
mod tests;

mod activation;
mod callers;
pub(crate) mod capture;
