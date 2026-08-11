# Aya uprobe offset semantics — pinned (Phase 1a, Task 3)

**Fact:** aya 0.14.0 `UProbeAttachLocation::AbsoluteOffset(u64)` is an ELF
**object-file byte offset** — exactly what `p11scope-discover` records per
manifest entry. No vaddr translation happens at attach time; aya passes the
value through to the kernel, which expects file offsets for uprobes.

**Evidence** (spike/aya-offset-pin/run.sh, kernel 7.0.0-28-generic, aya =0.14.0,
aya-ebpf =0.2.1): non-PIE target, `probe_me` vaddr 0x401106, file offset
0x1106. Attach at file offset → hits=7/7. Attach at vaddr →
attach_error=`perf_event_open` failed. Source cross-reference: aya-0.14.0
`src/programs/uprobe.rs` documents AbsoluteOffset as "The offset in the
target object file, in bytes" and provides
`UProbeAttachLocation::from_virtual_address` for callers holding vaddrs.

**Consequence for Phase 1b:** attach with
`UProbeAttachLocation::AbsoluteOffset(manifest_entry.file_offset)` directly.
Never re-derive offsets from symbol tables (providers are stripped).
