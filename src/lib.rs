//! p11scope — non-interposing PKCS#11 observer (eBPF uprobes).

pub mod attach;
pub mod discover_cmd;
pub mod metrics;
pub mod plan;
pub mod render;
pub mod scope;
pub mod verify;

/// The BPF object, built by build.rs. Alignment matters: aya parses it
/// as ELF in place.
pub static EBPF_OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/p11scope-ebpf"));
