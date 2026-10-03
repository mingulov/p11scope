//! SPDX-License-Identifier: GPL-3.0-or-later
//! Discovery: how the observer learns which objects/offsets to probe and pins their
//! identity. Slice 1a: manifest input only (`identity`). Slice 1b adds scan/live/pause.
pub mod attribution;
pub(crate) mod caller_registry;
pub mod engine;
pub mod hooks;
pub mod identity;
pub(crate) mod inventory_attach_set;
pub mod inventory_workload;
pub(crate) mod loader;
pub mod noise;
pub(crate) mod pause;
pub mod scan;
pub(crate) mod scheduler;
pub(crate) mod sweep_attribution;

#[cfg(test)]
mod test_subject;
