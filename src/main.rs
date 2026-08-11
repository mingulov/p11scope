//! p11scope — non-interposing PKCS#11 observer (eBPF uprobes).

mod attach;
mod plan;
mod scope;

/// The BPF object, built by build.rs. Alignment matters: aya parses it
/// as ELF in place.
pub static EBPF_OBJECT: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/p11scope-ebpf"));

fn main() {
    eprintln!("p11scope 0.0.0-dev — use `p11scope profile --manifest … --pid …`");
    std::process::exit(2);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// build.rs must embed the real cross-compiled BPF object, never a
    /// placeholder byte array — a stub would silently break every attach.
    #[test]
    fn ebpf_object_is_a_real_bpf_elf() {
        assert!(EBPF_OBJECT.len() > 1000, "expected a real BPF object, not a stub");
        assert_eq!(&EBPF_OBJECT[..4], b"\x7fELF", "embedded object is not an ELF file");
    }
}
