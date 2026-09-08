# Local aya-obj patch

Based on the published `aya-obj 0.3.0` package, registry checksum
`8c76b9c75d9cdc155ff8f6a06d61e873f67bf47be8cfa92a3b5aaea43f4b4077`,
upstream commit `269dfaf4a20b99f2e3d384e3e5d13b226f507360`.
Upstream licenses and sources are retained; `.cargo-ok` is a registry cache marker
and is excluded. The empty workspace declaration permits standalone tests from
inside a worktree. Package dependencies and its published lockfile are unchanged.

The relocation patch resolves local map references by their section and exact
definition offset. Multiple maps can share `.maps`; treating that section as one
map caused a debug assertion and arbitrary descriptor selection. Whole-section
fallback remains for global data maps. Missing and ambiguous definition offsets
are errors. Named references and global-data value offsets retain their behavior.
The addend follows the [LLVM BPF relocation format](https://docs.kernel.org/bpf/llvm_reloc.html).

The crate's tests cover distinct, unsigned, missing, interior and ambiguous map
offsets and unchanged global-data relocation. The application's
`tests/bpf_map_contracts.rs` also relocates its actual embedded object without
kernel syscalls and checks that all required native maps remain distinct.

Run the upstream and added unit tests with:

```sh
cargo +1.88 test --locked --manifest-path third-party/aya-obj/Cargo.toml --target-dir target --lib
```

This patch changes object relocation only. Kernel verifier, map-freeze, attachment,
capture and per-kernel qualification remain separate acceptance checks.
