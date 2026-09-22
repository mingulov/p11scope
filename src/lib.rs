//! SPDX-License-Identifier: GPL-3.0-or-later
//! p11scope — non-interposing PKCS#11 observer (eBPF uprobes).

pub mod attach;
pub mod capacity;
pub mod cli;
pub mod discovery;
pub mod doctor;
pub mod events;
pub mod inspect;
pub mod kinds;
pub mod manifest_input;
pub mod metrics;
pub mod output;
pub mod plan;
pub mod process;
pub mod render;
pub(crate) mod run;
pub mod scope;
pub mod semantics;
pub mod shapes;
pub(crate) mod sink;
pub mod trace;
pub(crate) mod uretprobe_hazard;

/// The whole public production surface of the capture loops. `run` stays a
/// crate-private module: the owned child, the pause coordinator, its clocks,
/// maps, drains, guards and injected actions are unreachable from outside.
pub use run::{OwnedRunOutcome, capture, run_owned};

/// The BPF object, built by build.rs. Alignment matters: aya parses it
/// as ELF in place.
pub static EBPF_OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/p11scope-ebpf"));

/// Dedicated endpoint-use inventory object. It has no ordinary call event or
/// return/latency state; loader preparation is a separate capability contract.
pub static EBPF_INVENTORY_OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/p11scope-ebpf-inventory"));

pub(crate) mod history;
