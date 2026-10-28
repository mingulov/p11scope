//! SPDX-License-Identifier: GPL-3.0-or-later
//! Discovery: how the observer learns which objects/offsets to probe and pins their
//! identity. Slice 1a: manifest input only (`identity`). Slice 1b adds scan/live/pause.
pub mod attribution;
pub(crate) mod caller_registry;
pub(crate) mod confirm_shards;
pub mod engine;
pub mod hooks;
pub mod identity;
// Task 3 Stage A router: consumed by the Task 6 native seam (DR-T3A-1) and
// today by the privileged instance gates and its unit regressions.
#[allow(dead_code)]
pub(crate) mod instances;
pub(crate) mod inventory_attach_set;
pub mod inventory_workload;
// D3b custody substrate; production backend selection follows in D3c/D3d.
#[allow(dead_code)]
pub(crate) mod kernel_identity;
pub(crate) mod loader;
// L1 staged loader-lifetime token/generation model (G16). Production
// allocation stays on loader.rs's refusal path until L2/L3 land atomically;
// L3's Engine acknowledgement wires the retirement/fence API.
#[allow(dead_code)]
pub(crate) mod loader_lifetime;
pub(crate) mod native_binding;
pub mod noise;
pub(crate) mod pause;
pub(crate) mod proof_stats;
// Z2 retained-member custody substrate; the Task 3 N1 confirm-path routing
// is its first consumer (remove once it consumes the whole surface).
#[allow(dead_code)]
pub(crate) mod retained_member;
pub mod scan;
pub(crate) mod scheduler;
pub(crate) mod sweep_attribution;
pub(crate) mod sweep_shards;

#[cfg(test)]
mod test_subject;
