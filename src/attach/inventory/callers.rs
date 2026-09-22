//! SPDX-License-Identifier: GPL-3.0-or-later
//! Private caller preparation, exact map contract, immutable endpoint
//! publication and retained health for the dedicated caller object.

use super::{
    AttachBackend, BPF_F_RDONLY_PROG, ExactMapMetadata, InventoryBudget, InventoryMapKind,
    InventoryPreparation, compare_map_metadata, inventory_capacity, inventory_map_data,
    inventory_maps, map_metadata, prepare_inventory_with_kind, read_map_metadata,
};
use crate::capacity::CallerBudget;
use crate::discovery::identity::PinnedObjectId;
use anyhow::{Result, bail};
use aya::Ebpf;
use aya::maps::{Array, MapType, PerCpuArray};
use p11scope_ebpf_common::inventory_callers::EndpointObject;
use p11scope_ebpf_common::{IMAGE_IDENTITY_TICKET_LIMIT, ImageIdentityControl};
use std::collections::BTreeMap;
use std::time::Instant;

pub(super) fn validate_caller_maps(
    actual: &BTreeMap<String, (InventoryMapKind, ExactMapMetadata)>,
    budget: CallerBudget,
) -> Result<()> {
    use InventoryMapKind as K;
    let n = inventory_capacity(budget.endpoint_budget())?;
    let p = u32::try_from(budget.pair_limit())?;
    let mut expected = inventory_maps(n);
    expected.extend([
        (
            "ENDPOINT_OBJECT",
            (
                K::Array,
                map_metadata(MapType::Array, 4, 8, n.get(), BPF_F_RDONLY_PROG),
            ),
        ),
        (
            "CALLER_USE",
            (K::Hash, map_metadata(MapType::Hash, 24, 32, p, 0)),
        ),
        (
            "CALLER_EVIDENCE",
            (
                K::PerCpuArray,
                map_metadata(MapType::PerCpuArray, 4, 8, 4, 0),
            ),
        ),
        (
            "TASK_COOKIE",
            (
                K::Unsupported,
                map_metadata(MapType::TaskStorage, 4, 8, 0, 1),
            ),
        ),
        (
            "COOKIE_CTL",
            (K::Array, map_metadata(MapType::Array, 4, 40, 1, 0)),
        ),
    ]);
    if !actual
        .keys()
        .map(String::as_str)
        .eq(expected.keys().copied())
    {
        bail!("caller Inventory map names differ from exact 18-map manifest");
    }
    for (name, (kind, metadata)) in expected {
        let (actual_kind, actual_metadata) = actual[name];
        if actual_kind != kind {
            bail!("caller Inventory {name} map variant differs");
        }
        compare_map_metadata(name, actual_metadata, metadata)?;
    }
    Ok(())
}

pub(super) fn validate_caller_control(control: ImageIdentityControl) -> Result<()> {
    if [
        control.limit,
        control.next_ticket,
        control.unavailable,
        control.create_failures,
        control.retry_exhausted,
    ] != [IMAGE_IDENTITY_TICKET_LIMIT, 0, 0, 0, 0]
    {
        bail!("COOKIE_CTL is not a fresh caller identity control");
    }
    Ok(())
}

pub(super) fn prepare_caller_inventory_with<T>(
    endpoint_budget: InventoryBudget,
    caller_budget: CallerBudget,
    backend: AttachBackend,
    state: T,
    operation: impl FnMut(&mut T, InventoryPreparation) -> Result<()>,
) -> Result<T> {
    if endpoint_budget != caller_budget.endpoint_budget() {
        bail!("caller endpoint budget differs from Inventory budget");
    }
    prepare_inventory_with_kind(backend, state, true, operation)
}

pub(super) fn validate_runtime_caller_maps(ebpf: &Ebpf, budget: CallerBudget) -> Result<()> {
    let actual = ebpf
        .maps()
        .map(|(name, map)| {
            let (kind, data) = inventory_map_data(name, map)?;
            Ok((name.to_string(), (kind, read_map_metadata(name, data)?)))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    validate_caller_maps(&actual, budget)
}

impl CallerEndpointIo for Ebpf {
    fn read_endpoint(&mut self, endpoint: u32) -> Result<EndpointObject> {
        let map: Array<_, EndpointObject> = Array::try_from(
            self.map("ENDPOINT_OBJECT")
                .ok_or_else(|| anyhow::anyhow!("ENDPOINT_OBJECT map missing"))?,
        )?;
        Ok(map.get(&endpoint, 0)?)
    }

    fn write_endpoint(&mut self, endpoint: u32, value: EndpointObject) -> Result<()> {
        let mut map: Array<_, EndpointObject> = Array::try_from(
            self.map_mut("ENDPOINT_OBJECT")
                .ok_or_else(|| anyhow::anyhow!("ENDPOINT_OBJECT map missing"))?,
        )?;
        Ok(map.set(endpoint, value, 0)?)
    }
}

pub(super) trait CallerEndpointIo {
    fn read_endpoint(&mut self, endpoint: u32) -> Result<EndpointObject>;
    fn write_endpoint(&mut self, endpoint: u32, value: EndpointObject) -> Result<()>;
}

pub(super) fn publish_caller_endpoint_with<I: CallerEndpointIo>(
    io: &mut I,
    endpoint: u32,
    object: PinnedObjectId,
) -> Result<()> {
    let old = io.read_endpoint(endpoint)?;
    if !old.is_uncommitted() {
        bail!("caller endpoint {endpoint} is already committed or malformed");
    }
    let value = EndpointObject {
        object_id: object.0,
        class: p11scope_ebpf_common::inventory_callers::ENDPOINT_OBJECT_COMMITTED_PHYSICAL,
    };
    io.write_endpoint(endpoint, value)?;
    if io.read_endpoint(endpoint)? != value {
        bail!("caller endpoint {endpoint} readback differs from committed physical object");
    }
    Ok(())
}

pub(super) trait CallerHealthIo {
    fn evidence_cell(&mut self, index: u32) -> Result<u64>;
    fn identity_control(&mut self) -> Result<ImageIdentityControl>;
}

#[derive(Debug, Default)]
pub(super) struct CallerHealth {
    pub evidence: Option<[u64; 4]>,
    pub control: Option<ImageIdentityControl>,
    pub failures: Vec<String>,
}

pub(super) fn read_caller_health_with<I: CallerHealthIo>(
    io: &mut I,
    deadline: Instant,
) -> CallerHealth {
    let mut health = CallerHealth::default();
    let mut evidence = [0u64; 4];
    let mut unknown = false;
    for (index, value) in evidence.iter_mut().enumerate() {
        if Instant::now() >= deadline {
            health.failures.push(format!(
                "caller health deadline before CALLER_EVIDENCE[{index}]"
            ));
            unknown = true;
            continue;
        }
        match io.evidence_cell(index as u32) {
            Ok(read) => *value = read,
            Err(error) => {
                health
                    .failures
                    .push(format!("CALLER_EVIDENCE[{index}]: {error:#}"));
                unknown = true;
            }
        }
    }
    if !unknown {
        health.evidence = Some(evidence);
    }
    if Instant::now() >= deadline {
        health
            .failures
            .push("caller health deadline before COOKIE_CTL".into());
    } else {
        match io.identity_control() {
            Ok(control) => health.control = Some(control),
            Err(error) => health.failures.push(format!("COOKIE_CTL: {error:#}")),
        }
    }
    health
}

impl CallerHealthIo for &Ebpf {
    fn evidence_cell(&mut self, index: u32) -> Result<u64> {
        let map: PerCpuArray<_, u64> = PerCpuArray::try_from(
            self.map("CALLER_EVIDENCE")
                .ok_or_else(|| anyhow::anyhow!("CALLER_EVIDENCE map missing"))?,
        )?;
        map.get(&index, 0)?.iter().try_fold(0u64, |sum, value| {
            sum.checked_add(*value)
                .ok_or_else(|| anyhow::anyhow!("CALLER_EVIDENCE[{index}] per-CPU sum overflow"))
        })
    }

    fn identity_control(&mut self) -> Result<ImageIdentityControl> {
        let map: Array<_, ImageIdentityControl> = Array::try_from(
            self.map("COOKIE_CTL")
                .ok_or_else(|| anyhow::anyhow!("COOKIE_CTL map missing"))?,
        )?;
        Ok(map.get(&0, 0)?)
    }
}

#[cfg(test)]
mod tests;
