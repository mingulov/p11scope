//! p11scope — non-interposing PKCS#11 observer (eBPF uprobes).

pub mod attach;
pub mod cli;
pub mod discovery;
pub mod events;
pub mod inspect;
pub mod kinds;
pub mod manifest_input;
pub mod metrics;
pub mod output;
pub mod plan;
pub mod process;
pub mod render;
pub mod scope;
pub mod semantics;
pub mod shapes;
pub mod trace;

/// The BPF object, built by build.rs. Alignment matters: aya parses it
/// as ELF in place.
pub static EBPF_OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/p11scope-ebpf"));
