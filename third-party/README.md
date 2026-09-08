# Local dependency corrections

## Aya 0.14.0

`aya/` contains the published `aya` 0.14.0 package, selected by the root
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

CI runs this explicit dependency gate after the root workspace tests, because
the root workspace excludes Aya. Developers can run the same command from the
repository root (use an external `CARGO_TARGET_DIR` for isolated evidence):

```sh
CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true cargo +1.88 test --locked --manifest-path third-party/aya/Cargo.toml --lib
```

When validating changes to this patch, also repeat the focused `maps::ring_buf::tests`
filter in debug with overflow checks, release with overflow checks, and ordinary
release. Repository release gates and supported-kernel runtime qualification
remain separate. Source export and offline packaging must retain this path
package; vendoring registry dependencies alone does not include it.

When replacing this copy with an upstream release, verify both production
corrections and the same reader regressions before removing the patch. Do not
edit the shared Cargo registry cache.
