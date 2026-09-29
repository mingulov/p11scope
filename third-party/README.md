<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Local dependency corrections

## Release attribution

`licenses/sources.json` records immutable provenance and SHA-256 hashes for
original upstream license texts used by release packaging. The corresponding
text files under `licenses/` preserve upstream terms and copyright notices;
they do not change p11scope's GPL license. This includes the Aya notices for
the source fragments retained in the patch files below.

`scripts/release-notices.py` inventories both locked Cargo workspaces and
preserves original licensing files independently of the selected SPDX
alternative. It adds pinned Rust library reports, native runtime notices and
musl 1.2.3/1.2.5 source archives, including their per-file notices. The
inventory includes build, development and non-Linux dependencies and does not
claim that every listed package is linked into each release binary. Generated
bundles remain outside this source tree. See [the release runbook](../RELEASING.md).

The small `p11scope-bpf-multi` support crate also borrows the raw multi-link
UAPI layout and bounded attach bisection from
[osslscope's BPF helper](https://github.com/mingulov/osslscope/blob/807dbba8f06c0d215f1c43c57090fe6c3436896f/crates/bpf-sys/src/lib.rs)
and [capture planner](https://github.com/mingulov/osslscope/blob/807dbba8f06c0d215f1c43c57090fe6c3436896f/src/plan.rs).
Those source routines were compared at the linked revision during release
review; the original import did not record its exact upstream checkout.
osslscope is by Denis Mingulov and uses GPL-3.0-or-later. p11scope's subsequent
layout, error handling and integration changes remain in its own Git history.
The Aya attach semantics and their upstream revision are described below.

## Source reconstruction

`sources.json` is the source of truth for reconstructed packages. From a fresh
checkout, `python3 -I scripts/prepare-dependencies.py` obtains and verifies the
pinned archives; `--archive-dir DIRECTORY` supplies those archives explicitly.
For offline use, populate `third-party/archives/` and pass `--offline`. The
generated trees and receipts under `src/` are ignored, while `sources.json` and
all files under `patches/` remain tracked.

## Aya 0.14.0

`src/aya-0.14.0-p2/` is reconstructed from the published `aya` 0.14.0 package
and the ordered patches in `patches/aya-0.14.0/`, then selected by the root
`[patch.crates-io]` while the dependency remains `aya = "=0.14.0"`. Its original
MIT and Apache-2.0 license files, upstream attribution, and registry dependency
declarations are retained. This is one package, not the Aya workspace.

Published input:

- Archive: <https://static.crates.io/crates/aya/aya-0.14.0.crate>
- SHA-256: `66e644424fada9fff4fdc63848db1732fb69b626e8328202ef55c03df1f4d939`
- Upstream revision recorded in `.cargo_vcs_info.json`:
  `302985c72850cd9a8f1d791a11d247a4fbe1c5b1`
- Original package: 89 regular files, 1,151,212 uncompressed bytes.

The local production correction is confined to `src/maps/ring_buf.rs`:

1. The read-only producer-position and record-header atomics use Relaxed loads
   immediately followed by Acquire fences. This follows the documented
   [Rust 1.88 read-only atomic contract](https://github.com/rust-lang/rust/blob/1.88.0/library/core/src/sync/atomic.rs#L157)
   for loads up to eight bytes on the supported x86-64 observer. Existing
   Release cursor publication and SeqCst wakeup fences remain intact.
2. The consumer cursor explicitly wraps after the same aligned record advance.
   Checked arithmetic previously panicked when an eight-byte payload advanced
   `usize::MAX - 15` to zero.

Native tests in `src/maps/ring_buf/tests.rs` exercise the actual private reader,
cursor, item Drop, discard, and BUSY paths. Fully initialized owned temporary
files provide real read-only producer/data mappings and writable consumer
metadata. Aya's existing unit-test mmap hook supplies those real mapping
pointers to its constructors; test guards restore the hook and unmap only after
the reader is destroyed. These finite regular-file tests do not emulate kernel
double-map aliasing or qualify actual BPF producer behavior. Passing on x86-64
does not by itself prove the read-only atomic language contract.

Two additional integration adjustments are limited to testing/build ownership:

- An empty `[workspace]` boundary is appended to Aya's normalized manifest,
  preserving every package and dependency field. Root workspace exclusion alone
  let Cargo find an enclosing checkout's workspace during standalone tests.
- Four existing test assertions in `src/programs/uprobe.rs` compare against
  `Path::new` literals. The original `Path`/`str` comparisons fail to compile on
  Rust 1.88; the asserted paths are unchanged.

The published Aya `Cargo.lock` is retained for standalone tests. The root
lockfile retains all dependency versions and checksums except Aya's registry
source/checksum, replaced by this local path selection. Package metadata and
the resolved dependency graph must be compared when refreshing this patch.

Revision 2 adds a narrow backport of upstream Aya PR #1417 ("aya: add
multi-uprobe attach support", by `swananan`, merged 2026-07-31 as
`5c1a79e0bdc36e77`), minus symbol batching: `AttachMode`
(Single/Multi/Unknown) selected from the ELF section kind, program load
with `BPF_TRACE_UPROBE_MULTI` (48) for multi sections, raw
`bpf_link_create_uprobe_multi`, per-point cookies, `ProbeLinkInner`
one/many links, pid mapping (AllProcesses to 0, CallingProcess to the
real pid, OneProcess to its pid), and Unknown-mode fallback (multi
first, singles on `MultiLinkNotSupported`/EINVAL). Multi-point symbol
resolution stays sequential through the existing single-symbol path;
p11scope attaches `AbsoluteOffset` only. One p11scope-only extension:
`UProbe::load_multi`, which selects the multi load flag explicitly —
p11scope keeps plain `uprobe`/`uretprobe` sections and chooses the
backend at runtime behind a functional probe. Upstream's MIT/Apache-2.0
terms still apply to the backported lines; no new dependency is added
(the upstream `rstest` test dependency is deliberately not vendored, so
the new behavior is pinned by the application's own tests instead).

CI reconstructs and validates both dependency graphs before the root workspace
gates, then runs this explicit dependency gate because the root workspace
excludes Aya. Developers can run the same command from the repository root;
the target directory remains outside the immutable generated package. The
`--offline` form assumes the locked Cargo dependencies are already cached:

```sh
CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true cargo +1.88 test --locked --offline --manifest-path third-party/src/aya-0.14.0-p2/Cargo.toml --target-dir target/aya-tests --lib
```

When validating changes to this patch, also repeat the focused `maps::ring_buf::tests`
filter in debug with overflow checks, release with overflow checks, and ordinary
release. Repository release gates and supported-kernel runtime qualification
remain separate. Source exports omit generated trees and must retain
`sources.json`, every named patch, and the exact archives when the export must
reconstruct without network access. The generated `aya-obj` package is
`src/aya-obj-0.3.0-p2/`; its standalone test target is `target/aya-obj-tests`.
Its revision 2 carries the matching `ProgramSection` half of the Aya PR #1417
backport: the `multi` flag plus the `uprobe.multi`, `uprobe.multi.s`,
`uretprobe.multi`, and `uretprobe.multi.s` section spellings.

When replacing this copy with an upstream release, verify both production
corrections and the same reader regressions before removing the patch. Do not
edit the shared Cargo registry cache.
