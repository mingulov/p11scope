# Reproducible dependency patch series

Status: selected architecture; implementation and migration checks remain pending.

## Purpose

Maintain local dependency fixes as reviewable patches against pinned upstream
sources. A fresh checkout must reconstruct the same modified sources before
Cargo resolves dependencies. Adding another supported dependency or patch must
require data and Cargo configuration changes, not another package-specific
branch in the preparation code.

The initial migration covers Aya 0.14.0 and aya-obj 0.3.0. Their current source
copies are committed in `35fc237`; preserve every file until reconstruction and
build-input verification pass. This migration changes source distribution,
not dependency versions, application behavior, or the privacy allowlist.

## Selected approach and alternatives

Use a small Python standard-library preparation tool, Git's patch application,
and a finite manifest of crates.io archives with ordered patch series. Cargo
continues to resolve versions and features. Preparation runs before Cargo;
`build.rs` cannot create dependency manifests early enough.

Full copied sources already work after checkout, but obscure local changes.
Git forks can provide Cargo sources but introduce separate repository history
and publication requirements. Cargo vendoring remains useful for offline
registry/Git dependencies; it does not itself manage local patch series. An
additional patch-management dependency is justified only if it meets the
same bootstrap, immutable-output, and receipt requirements with less code.

## Maintained inputs

- `third-party/sources.json` has a schema version, the Cargo workspace manifest
  paths to verify, and a finite list of package records.
- Each record has an exact crate name/version, positive local revision,
  archive SHA-256, ordered patch paths,
  expected complete source-tree digest, and `applies_to` workspace paths.
- Archive URLs derive from validated crate name/version and the fixed
  `https://static.crates.io/crates/` origin. Version 1 accepts crates.io source
  archives only. Git/native/toolchain patches require a separate concrete
  need before adding another source adapter.
- Patches live under `third-party/patches/<name>-<version>/`, one logical fix
  with its regression tests per patch. Use an explicit sequence in the
  manifest; filename sorting is not authority.
- `third-party/README.md` records each patch's reason, upstream base, upstream
  status or link when available, applicable regression test, and removal
  condition. Do not invent an upstream issue or submit one automatically.

The initial series preserves these independent changes:

| Package | Logical changes |
| --- | --- |
| Aya | Standalone workspace; ring reader fixes and native tests; Rust 1.88 test compatibility |
| aya-obj | Standalone workspace; map relocation correction, regression tests and existing local provenance note |

Unmodified upstream task-storage classification is not a local patch.
Application adapters such as map freezing remain application code; the
inventory did not establish a need to move them into dependency patches.

## Preparation and immutable outputs

`scripts/prepare-dependencies.py` reads its repository root from its own
location. It supports normal preparation, `--offline`, `--archive-dir DIR`,
and read-only `--check`. Tests run directly with Python, before any Cargo
dependency manifest is needed. No global Cargo configuration or cache is
modified.

Prepared sources live at
`third-party/src/<name>-<version>-p<revision>/`. Cargo overrides name those
directories explicitly. Archive or patch changes require a new revision and
new output directory. There is no mutable `current` symlink, automatic Cargo
manifest rewriting, or automatic deletion of older outputs.

The preparer has finite archive-size, expanded-size and entry-count limits;
these are tool policy, not repeated fields in every package record.
Preparation verifies the archive digest before parsing, validates all archive
members before materialization, applies patches in order to a private staging
tree, and verifies the complete result before publication. Reject traversal,
absolute paths, duplicate members, symlinks, hardlinks, sparse/special files,
and unsupported permission bits. Support directories and regular files with
normalized 0755 directory and 0644/0755 file modes; executable intent must be
represented in the expected tree digest. Ignore ownership and timestamps.
Reject non-UTF-8 paths, backslashes and control characters so ledger records
have one unambiguous line per file.

The tree digest is SHA-256 over `p11scope-prepared-tree-v2\0`, followed for
each file in UTF-8 relative-path byte order by path, NUL, four-digit octal mode,
NUL, lowercase content SHA-256, NUL. Extra, missing, modified or symlinked
files fail verification. A stamp is never a substitute for checking bytes.
Patch paths must remain within the staged package. Use `git apply` and require
its successful exit for every patch; a separate check-then-apply pass adds no
protection inside the disposable private stage. Apply
without reverse, three-way, reject-file, unsafe-path or whitespace-fixing
fallbacks, then verify the expected full tree.

A reserved `.p11scope-prepared.json` receipt records a versioned recipe identity
derived from the normalized package record and actual ordered patch bytes.
It is created by the preparer, cannot be supplied by an archive or patch, and
is excluded from the upstream-plus-patches tree digest. Include it in build
input ledgers. Reuse requires both recipe identity and tree verification, so
changing a same-revision recipe is refused even if its final bytes match.
There is no duplicate list of manually maintained patch hashes.

A stable checkout-local lock serializes preparers. Publish each verified
package by rename only when its destination is absent; an existing exact tree
is an idempotent success and an existing different tree is a named refusal.
Never overwrite a published tree during a build. A failure between package
publications is recoverable by verifying the first and preparing the missing
remainder. Ordinary failure removes only that invocation's private stage;
an interrupted stage cannot become an accepted source.

## Build entry point and source binding

The documented automatic command is `scripts/cargo.sh +1.88 build --locked`.
The wrapper prepares sources before executing Cargo. Developers may also run
preparation once and then direct Cargo commands. Keep Rust 1.88 and edition
2024. The wrapper does not claim to make ordinary dependencies or toolchains
available offline.

Source-tree verification alone cannot prove that Cargo selected that tree.
`scripts/check-prepared-dependencies.py` consumes the recipe and Cargo-produced
metadata JSON. It verifies each reachable patched package's name, version and
exact manifest path against the applicable record. Reject any reachable
generated source absent from the expected mapping, including an older retained
revision. Do not implement dependency resolution or parse Cargo TOML in this
tool.

The root workspace includes the discovery helper. The BPF crate is a separate
workspace. The initial Aya records apply to the root workspace only; BPF
currently has no local source override. Future transitive or multiple-version
patches require explicit Cargo source/alias wiring and workspace applicability.
Root overrides must never be assumed to propagate to another workspace.

For build receipts, obtain locked, offline Cargo metadata with all features
for the root and BPF manifests, using the respective pinned toolchains, after
tool/input selection and before build or privileged resources. Preserve the
metadata command, output and status. Emit generated-file ledger rows only
after graph binding and full source-tree verification both succeed. At receipt
completion, recheck recipe, Cargo manifests/locks, and generated bytes; changed
identity inputs invalidate the receipt. No download belongs inside sealed
release execution.

CI acquires ordinary locked dependencies for both workspaces outside sealed
execution before running offline metadata verification. This acquisition is
separate from the two patched archive downloads; a warm Cargo cache is not
a fresh-checkout requirement. CI performs the same graph-binding check.
The graph checker reuses the preparer's recipe and tree verification code
rather than maintaining a second implementation. Aya standalone tests resolve a
registry aya-obj from Aya's own lockfile; retain those tests, and separately
verify/test the root graph containing both local replacements. Do not describe
the standalone suite as integrated local aya-obj coverage.

## Caller and archive closure

Prepare before the first manifest-resolving Cargo command in CI and root
gates. Store standalone dependency test targets outside prepared source trees.
Use one verified generated-source ledger at these current boundaries:

- Release and lane16 start/end snapshots.
- Knative and ABI-routing input inventories.
- Host preparation before container helper vendoring and read-only mounts.
- Offline source export and fresh extraction verification.

Collectors must iterate the verified manifest output, not contain an Aya-only
path list. Preserve unrelated-untracked-input refusal and target-output
exclusions. Test ordering with controlled resource markers, without launching
real containers merely to test source-input admission.

An offline source archive contains maintained recipes, patches, preparation
tools, and original checksum-pinned `.crate` archives. It reconstructs sources
after extraction with no `.git`, original checkout, shared registry source
copy, or network. Ordinary locked dependencies, BPF inputs, toolchains and
host tools remain additional offline-build requirements.

## Updates, retirement and acceptance

For every dependency refresh, check the upstream status of each local patch.
Test the relevant regression against the proposed upstream version before
retiring a patch. Rebase surviving logical patches on the new pinned archive,
increment the revision, update Cargo wiring, and review the complete resulting
delta. Successful patch application alone does not establish correctness.

Acceptance requires synthetic preparation/failure/concurrency tests, byte
equality for all 131 current package files with their intended modes, unchanged
locked dependency selection, actual fresh-checkout and offline-extraction
checks, source-binding rejection for stale Cargo overrides, and every caller
above recording both selected local packages. Run the root and standalone
dependency gates appropriate to the migration. Record unrelated existing
release failures separately; do not label the release qualified from these
checks.

Use incremental local commits, with Luna handling exact staging/commit scope
after primary acceptance. Remove the tracked full copies only after their
replacement is working and verified, in a separate reviewable commit. No
push, tag or upstream publication is part of this work.

## Cargo references

- [Dependency overrides](https://doc.rust-lang.org/cargo/reference/overriding-dependencies.html)
- [Build scripts](https://doc.rust-lang.org/cargo/reference/build-scripts.html)
- [Vendoring](https://doc.rust-lang.org/cargo/commands/cargo-vendor.html)
- [Metadata](https://doc.rust-lang.org/cargo/commands/cargo-metadata.html)
