//! SPDX-License-Identifier: GPL-3.0-or-later
//! Root-owned gates; run explicitly with --ignored --test-threads=1.
use super::*;
use crate::capacity::CallerBudget;
use crate::discovery::identity::PinnedObjectId;
use aya::programs::{ProgramError, loaded_links};
use aya_obj::generated::bpf_cmd;
use std::collections::BTreeSet;
use std::os::fd::{AsFd as _, AsRawFd as _, FromRawFd as _, OwnedFd};
use std::time::{Duration, Instant};

fn budget(n: u32) -> InventoryBudget {
    InventoryBudget::new(u64::from(n), u64::from(n) * 8).unwrap()
}

#[derive(Default, Debug)]
struct OwnedIds {
    maps: BTreeSet<u32>,
    programs: BTreeSet<u32>,
}
impl OwnedIds {
    fn observe(&mut self, ebpf: &Ebpf) -> Result<()> {
        for (name, map) in ebpf.maps() {
            let id = inventory_map_data(name, map)?.1.info()?.id();
            anyhow::ensure!(
                id_exists(bpf_cmd::BPF_MAP_GET_NEXT_ID, id)?,
                "owned map {id} missing from ID registry"
            );
            self.maps.insert(id);
        }
        for (_, program) in ebpf.programs() {
            match program.info() {
                Ok(info) => {
                    let id = info.id();
                    anyhow::ensure!(
                        id_exists(bpf_cmd::BPF_PROG_GET_NEXT_ID, id)?,
                        "owned program {id} missing from ID registry"
                    );
                    self.programs.insert(id);
                }
                Err(ProgramError::NotLoaded) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn assert_no_links(&self) -> Result<()> {
        for link in loaded_links() {
            let link = link?;
            anyhow::ensure!(
                !self.programs.contains(&link.program_id()),
                "Inventory program {} has link {}",
                link.program_id(),
                link.id()
            );
        }
        Ok(())
    }

    fn wait_for_release(&self, fd_baseline: Option<usize>) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            let mut remaining = false;
            for (command, ids) in [
                (bpf_cmd::BPF_MAP_GET_NEXT_ID, &self.maps),
                (bpf_cmd::BPF_PROG_GET_NEXT_ID, &self.programs),
            ] {
                for id in ids {
                    remaining |= id_exists(command, *id)?;
                }
            }
            if !remaining && fd_baseline.is_none_or(|count| fd_count() == count) {
                return Ok(());
            }
            anyhow::ensure!(
                Instant::now() < deadline,
                "Inventory resources did not release within the bounded gate: {self:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn still_registered(&self) -> Result<Self> {
        let mut live = Self::default();
        for id in &self.maps {
            if id_exists(bpf_cmd::BPF_MAP_GET_NEXT_ID, *id)? {
                live.maps.insert(*id);
            }
        }
        for id in &self.programs {
            if id_exists(bpf_cmd::BPF_PROG_GET_NEXT_ID, *id)? {
                live.programs.insert(*id);
            }
        }
        Ok(live)
    }
}

fn id_exists(command: bpf_cmd, id: u32) -> Result<bool> {
    let start = id.checked_sub(1).context("BPF object ID must be nonzero")?;
    let mut attr = [start, 0u32, 0u32];
    // GET_NEXT_ID reads the registry without acquiring an object reference.
    // GET_FD_BY_ID is unsuitable here: reopening a program array after its
    // last user FD closes can retrigger deferred clearing and retain the map.
    // Registry removal proves release from that registry, not completion of
    // deferred kernel memory reclamation. The attr is start/next/open_flags.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            command as u32,
            &mut attr,
            std::mem::size_of::<[u32; 3]>(),
        )
    };
    if result == 0 {
        anyhow::ensure!(attr[1] > start, "BPF next ID did not advance");
        return Ok(attr[1] == id);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        Ok(false)
    } else {
        Err(error.into())
    }
}

fn fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

fn inspect_prepared(prepared: &PreparedInventory) -> Result<OwnedIds> {
    validate_runtime_inventory_maps(&prepared.ebpf, prepared.capacity)?;
    validate_runtime_inventory_programs(&prepared.ebpf)?;
    anyhow::ensure!(
        prepared.endpoint_capacity().get() as u64 == prepared.budget().endpoint_limit()
    );
    let cfg: Array<_, u64> = Array::try_from(prepared.ebpf.map("CONFIG").context("CONFIG")?)?;
    let expected = match prepared.scope {
        Scope::Pid(_) => 0x81,
        Scope::Cgroup { .. } => 0x82,
        Scope::System => 0xc0,
    };
    anyhow::ensure!(cfg.get(&0, 0)? == expected && cfg.get(&1, 0)? == 0);
    let usage: Array<_, u64> = Array::try_from(prepared.ebpf.map("USAGE").context("USAGE")?)?;
    anyhow::ensure!(usage.get(&0, 0)? == 0 && usage.get(&(prepared.capacity.get() - 1), 0)? == 0);
    let config: Array<_, InventoryUsageConfig> =
        Array::try_from(prepared.ebpf.map("USAGE_CONFIG").context("USAGE_CONFIG")?)?;
    validate_inventory_usage_config(prepared.capacity, usage.len(), config.get(&0, 0)?)?;
    let owner: Array<_, ThreadOwnerControl> =
        Array::try_from(prepared.ebpf.map("OWNER_CTL").context("OWNER_CTL")?)?;
    validate_inventory_owner_control(owner.get(&0, 0)?)?;
    let discovery = prepared.ebpf.map("DISCOVERY").context("DISCOVERY")?;
    anyhow::ensure!(
        prepared.discovery_domain.id()
            == u64::from(inventory_map_data("DISCOVERY", discovery)?.1.info()?.id())
    );
    let worker = prepared
        .ebpf
        .program("interface_list_worker")
        .context("worker")?
        .info()?
        .id();
    let tails = prepared.ebpf.map("TAIL_CALLS").context("TAIL_CALLS")?;
    anyhow::ensure!(super::super::program_array_id("TAIL_CALLS", tails, 0)? == Some(worker));
    anyhow::ensure!(super::super::program_array_id("TAIL_CALLS", tails, 1)?.is_none());
    let mut ids = OwnedIds::default();
    ids.observe(&prepared.ebpf)?;
    anyhow::ensure!(ids.maps.len() == 14 && ids.programs.len() == 12);
    let guard = prepared.ebpf.map("STACK_GUARD").context("STACK_GUARD")?;
    anyhow::ensure!(super::super::program_array_id("STACK_GUARD", guard, 0)?.is_none());
    ids.assert_no_links()?;
    eprintln!(
        "prepared {:?}, scope {}, N={}, IDs {ids:?}",
        prepared.backend,
        prepared.scope.kind(),
        prepared.capacity
    );
    Ok(ids)
}

#[test]
#[ignore = "requires privileged BPF, vmlinux BTF, exact-object verifier and cleanup accounting"]
fn privileged_inventory_preparation_loads_runtime_capacity_and_zero_links() -> Result<()> {
    for n in [1, 576, 4097] {
        let scopes = [
            Scope::System,
            Scope::Pid(std::process::id()),
            crate::scope::cgroup(std::path::Path::new("/sys/fs/cgroup"))?,
        ];
        for scope in scopes {
            let prepared = PreparedInventory::prepare(scope, budget(n), AttachBackend::Singles)?;
            let ids = inspect_prepared(&prepared)?;
            drop(prepared);
            ids.wait_for_release(None)?;
        }
    }
    Ok(())
}

#[test]
#[ignore = "requires privileged BPF and a kernel supporting the selected multi load backend"]
fn privileged_inventory_preparation_loads_multi_without_links() -> Result<()> {
    let prepared = PreparedInventory::prepare(Scope::System, budget(576), AttachBackend::Multi)?;
    let ids = inspect_prepared(&prepared)?;
    drop(prepared);
    ids.wait_for_release(None)
}

#[repr(C)]
struct MapElementAttr {
    map_fd: u32,
    pad: u32,
    key: u64,
    value: u64,
    flags: u64,
}

fn map_element<K, V>(
    command: bpf_cmd,
    map: &MapData,
    key: &K,
    value: Option<&V>,
) -> std::io::Result<()> {
    let attr = MapElementAttr {
        map_fd: map.fd().as_fd().as_raw_fd() as u32,
        pad: 0,
        key: std::ptr::from_ref(key) as u64,
        value: value.map_or(0, |value| std::ptr::from_ref(value) as u64),
        flags: 0,
    };
    // Observer-owned descriptors and live key/value buffers only.
    let result = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            command as u32,
            &attr,
            std::mem::size_of_val(&attr),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[test]
#[ignore = "requires privileged BPF; verifies every frozen map with valid observer-owned inputs"]
fn privileged_inventory_preparation_freezes_all_nine_protected_maps() -> Result<()> {
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) };
    anyhow::ensure!(
        pidfd >= 0,
        "pidfd_open: {}",
        std::io::Error::last_os_error()
    );
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as i32) };
    let owner_key = pidfd.as_raw_fd() as u32;
    let owner = p11scope_ebpf_common::ThreadOwner {
        original_pid_tgid: u64::from(std::process::id()) << 32 | u64::from(std::process::id()),
        discovery_cookies: [0; 64],
        occupied: 0,
        selection_domains: 0,
        start_count: 0,
        flags: 0,
    };
    let mut proved_task_key = false;
    let prepared = PreparedInventory::prepare_inner(
        Scope::System,
        budget(1),
        AttachBackend::Singles,
        |state, step| {
            if step == InventoryPreparation::ReadOwner {
                let map = inventory_map_data(
                    "THREAD_OWNER",
                    state.ebpf()?.map("THREAD_OWNER").context("THREAD_OWNER")?,
                )?
                .1;
                // Prove the key/input valid on this exact unfrozen map, then
                // restore fresh emptiness before the production freeze step.
                map_element(bpf_cmd::BPF_MAP_UPDATE_ELEM, map, &owner_key, Some(&owner))?;
                map_element::<_, u64>(bpf_cmd::BPF_MAP_DELETE_ELEM, map, &owner_key, None)?;
                proved_task_key = true;
            }
            Ok(())
        },
    )?;
    anyhow::ensure!(proved_task_key);
    let cgroup = std::fs::File::open("/sys/fs/cgroup")?;
    let worker_fd = prepared
        .ebpf
        .program("interface_list_worker")
        .context("worker")?
        .fd()?
        .as_fd()
        .as_raw_fd() as u32;
    for name in [
        "PID_FILTER",
        "CGROUP_FILTER",
        "USAGE_CONFIG",
        "THREAD_OWNER",
        "OWNER_CTL",
        "USAGE",
        "CONFIG",
        "TAIL_CALLS",
        "STACK_GUARD",
    ] {
        let map = inventory_map_data(name, prepared.ebpf.map(name).context("protected map")?)?.1;
        let result = match name {
            "PID_FILTER" => map_element(
                bpf_cmd::BPF_MAP_UPDATE_ELEM,
                map,
                &std::process::id(),
                Some(&1u64),
            ),
            "CGROUP_FILTER" => map_element(
                bpf_cmd::BPF_MAP_UPDATE_ELEM,
                map,
                &0u32,
                Some(&(cgroup.as_raw_fd() as u32)),
            ),
            "USAGE_CONFIG" => map_element(
                bpf_cmd::BPF_MAP_UPDATE_ELEM,
                map,
                &0u32,
                Some(&InventoryUsageConfig {
                    version: 1,
                    endpoint_capacity: 1,
                }),
            ),
            "THREAD_OWNER" => {
                map_element(bpf_cmd::BPF_MAP_UPDATE_ELEM, map, &owner_key, Some(&owner))
            }
            "OWNER_CTL" => map_element(
                bpf_cmd::BPF_MAP_UPDATE_ELEM,
                map,
                &0u32,
                Some(&ThreadOwnerControl {
                    limit: 64,
                    ..ThreadOwnerControl::default()
                }),
            ),
            "USAGE" => map_element(bpf_cmd::BPF_MAP_UPDATE_ELEM, map, &0u32, Some(&0u64)),
            "CONFIG" => map_element(bpf_cmd::BPF_MAP_UPDATE_ELEM, map, &0u32, Some(&0xc0u64)),
            "TAIL_CALLS" | "STACK_GUARD" => {
                map_element(bpf_cmd::BPF_MAP_UPDATE_ELEM, map, &0u32, Some(&worker_fd))
            }
            _ => unreachable!(),
        };
        anyhow::ensure!(
            result.as_ref().err().and_then(std::io::Error::raw_os_error) == Some(libc::EPERM),
            "{name} frozen-map update result: {result:?}"
        );
    }
    let ids = inspect_prepared(&prepared)?;
    drop(prepared);
    ids.wait_for_release(None)
}

#[test]
#[ignore = "requires privileged BPF; serial bounded failure/drop FD and exact object-ID accounting"]
fn privileged_inventory_preparation_failure_releases_owned_resources() -> Result<()> {
    let phases = [
        InventoryPreparation::LoadObject,
        InventoryPreparation::LoadProgram("function_list_entry", InventoryProgramLoad::UProbe),
        InventoryPreparation::RetainDiscovery,
    ];
    for _ in 0..3 {
        for failed in phases {
            let before = fd_count();
            let mut ids = OwnedIds::default();
            let error = PreparedInventory::prepare_inner(
                Scope::System,
                budget(576),
                AttachBackend::Singles,
                |state, step| {
                    ids.observe(state.ebpf()?)?;
                    if step == failed {
                        bail!("owned failure at {failed:?}");
                    }
                    Ok(())
                },
            )
            .err()
            .context("injected preparation unexpectedly succeeded")?;
            anyhow::ensure!(format!("{error:#}").contains("owned failure"), "{error:#}");
            ids.assert_no_links()?;
            ids.wait_for_release(Some(before))?;
        }
        let before = fd_count();
        let prepared =
            PreparedInventory::prepare(Scope::System, budget(576), AttachBackend::Singles)?;
        let ids = inspect_prepared(&prepared)?;
        drop(prepared);
        ids.wait_for_release(Some(before))?;
    }
    Ok(())
}

#[test]
#[ignore = "root-owned BPF lane; exact caller map/freeze and private ENDPOINT_OBJECT publication"]
fn privileged_inventory_caller_preparation_freezes_native_maps_and_publishes_binding() -> Result<()>
{
    use p11scope_ebpf_common::ImageIdentity;
    use p11scope_ebpf_common::inventory_callers::{
        CallerObjectKey, CallerObjectUse, EndpointObject,
    };
    let endpoint = budget(3);
    let caller = CallerBudget::new(endpoint, 5, 304).map_err(anyhow::Error::msg)?;
    let prepared = PreparedInventory::prepare_callers(
        Scope::System,
        endpoint,
        caller,
        AttachBackend::Singles,
    )?;
    callers::validate_runtime_caller_maps(&prepared.ebpf, caller)?;
    validate_runtime_inventory_programs(&prepared.ebpf)?;
    let mut ids = OwnedIds::default();
    ids.observe(&prepared.ebpf)?;
    anyhow::ensure!(ids.maps.len() == 19 && ids.programs.len() == 12);
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id(), 0) };
    anyhow::ensure!(
        pidfd >= 0,
        "pidfd_open: {}",
        std::io::Error::last_os_error()
    );
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as i32) };
    let task_key = pidfd.as_raw_fd() as u32;
    let key = CallerObjectKey {
        image: ImageIdentity {
            task_cookie: 1,
            exec_id: 0,
        },
        object_id: 0,
        reserved: 0,
    };
    let positive = CallerObjectUse {
        host_tgid: std::process::id(),
        witness_endpoint: 0,
        flags: 1,
        ..CallerObjectUse::default()
    };
    for name in ["TASK_COOKIE", "COOKIE_CTL", "CALLER_USE"] {
        let map = inventory_map_data(name, prepared.ebpf.map(name).context(name)?)?.1;
        let result = match name {
            "TASK_COOKIE" => map_element(bpf_cmd::BPF_MAP_UPDATE_ELEM, map, &task_key, Some(&1u64)),
            "COOKIE_CTL" => map_element(
                bpf_cmd::BPF_MAP_UPDATE_ELEM,
                map,
                &0u32,
                Some(&ImageIdentityControl {
                    limit: IMAGE_IDENTITY_TICKET_LIMIT,
                    ..Default::default()
                }),
            ),
            "CALLER_USE" => map_element(bpf_cmd::BPF_MAP_UPDATE_ELEM, map, &key, Some(&positive)),
            _ => unreachable!(),
        };
        anyhow::ensure!(
            result.as_ref().err().and_then(std::io::Error::raw_os_error) == Some(libc::EPERM),
            "{name} userspace write was not frozen: {result:?}"
        );
    }
    let mut prepared = prepared;
    callers::publish_caller_endpoint_with(&mut prepared.ebpf, 0, PinnedObjectId(0))?;
    let map: Array<_, EndpointObject> = Array::try_from(
        prepared
            .ebpf
            .map("ENDPOINT_OBJECT")
            .context("ENDPOINT_OBJECT")?,
    )?;
    anyhow::ensure!(
        map.get(&0, 0)?
            == EndpointObject {
                object_id: 0,
                class: 1
            }
    );
    anyhow::ensure!(
        callers::publish_caller_endpoint_with(&mut prepared.ebpf, 0, PinnedObjectId(0)).is_err(),
        "committed physical binding was rewritten"
    );
    let control: Array<_, ImageIdentityControl> =
        Array::try_from(prepared.ebpf.map("COOKIE_CTL").context("COOKIE_CTL")?)?;
    callers::validate_caller_control(control.get(&0, 0)?)?;
    ids.assert_no_links()?;
    eprintln!("I2C_CALLER_PREP_IDS phase=held step=Prepared ids={ids:?} links={{}}");
    eprintln!(
        "I2C_CALLER_PREPARED maps={} programs={} frozen=TASK_COOKIE,COOKIE_CTL,CALLER_USE endpoint0=object0",
        ids.maps.len(),
        ids.programs.len()
    );
    drop(prepared);
    ids.wait_for_release(None)?;
    eprintln!(
        "I2C_CALLER_PREP_IDS phase=released step=Prepared ids={:?} links={{}}",
        ids.still_registered()?
    );
    Ok(())
}

#[test]
#[ignore = "root-owned BPF lane; each caller native preparation fault retains source and releases IDs"]
fn privileged_inventory_caller_preparation_faults_release_exact_resources() -> Result<()> {
    let endpoint = budget(3);
    let caller = CallerBudget::new(endpoint, 5, 304).map_err(anyhow::Error::msg)?;
    for failed in [
        InventoryPreparation::WriteCallerControl,
        InventoryPreparation::ReadCallerControl,
        InventoryPreparation::Freeze("TASK_COOKIE"),
        InventoryPreparation::Freeze("COOKIE_CTL"),
        InventoryPreparation::Freeze("CALLER_USE"),
    ] {
        let before = fd_count();
        let mut ids = OwnedIds::default();
        let error = PreparedInventory::prepare_inner_flavor(
            Scope::System,
            endpoint,
            AttachBackend::Singles,
            InventoryFlavor::Callers(caller),
            |state, step| {
                ids.observe(state.ebpf()?)?;
                if step == failed {
                    anyhow::ensure!(ids.maps.len() == 19 && ids.programs.is_empty());
                    ids.assert_no_links()?;
                    eprintln!(
                        "I2C_CALLER_PREP_IDS phase=held step={failed:?} ids={ids:?} links={{}}"
                    );
                    bail!("owned caller fault at {failed:?}");
                }
                Ok(())
            },
        )
        .err()
        .context("caller fault was skipped")?;
        anyhow::ensure!(
            format!("{error:#}").contains("owned caller fault"),
            "{error:#}"
        );
        ids.assert_no_links()?;
        ids.wait_for_release(Some(before))?;
        eprintln!(
            "I2C_CALLER_PREP_IDS phase=released step={failed:?} ids={:?} links={{}}",
            ids.still_registered()?
        );
        eprintln!(
            "I2C_CALLER_PREP_FAULT step={failed:?} maps={} programs={}",
            ids.maps.len(),
            ids.programs.len()
        );
    }
    Ok(())
}
