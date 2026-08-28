# Task 4 Build-Subject and Blueprint Correction

**Status:** accepted after independent Sol, Terra, and Luna review on
2026-08-28. No build subject, executable contract, runtime lane, or release
evidence is claimed.

## Problem

The first blueprint candidate proved that selected source files plus `cargo`
do not close a Cargo build. Lanes 07, 09, 10, 11, and 16 currently rebuild the
workspace and therefore consume the workspace, locked crates, build scripts,
the Rust/eBPF toolchains and sysroots, linkers, their dynamic dependencies, and
generated objects. Repeating that transitive supply-chain surface in every
runtime lane is both fragile and unnecessary. Lane 09 additionally builds a
network-fed image from a broad Docker context.

The candidate is rejected. Canonical JSON and complete artifact-path coverage
do not compensate for an incomplete input trust boundary.

## Decision

Add one private build-subject freeze before runtime blueprint acceptance. It
produces the exact binaries and image used by runtime lanes. Lanes 07, 09, 10,
11, 16-never, and 16-auto consume private copied subjects and do not invoke
Cargo or build a container image. Lane 14 remains the source-bound build,
distribution, and portability contract; it is not the producer for earlier
runtime lanes.

This uses the existing contract schema and the existing lane-checker interface.
It adds no product option, generic adapter, nested-envelope schema, or semantic
behavior to the custody helper.

## Build-subject freeze

The freeze has two runs:

1. A rootless, non-production discovery build records a candidate literal
   ledger of every byte opened by Cargo, rustc, build scripts, eBPF Cargo,
   linkers, compilers, Docker-context processing, and executed build tools.
   It may discover authority but cannot produce an accepted subject.
2. After independent review fixes that literal ledger, a fresh production
   build at `build_head` consumes exactly the ledger under a clean environment.
   Any missing, changed, untracked, or additional input is non-pass.

Cargo is locked and offline. The ledger includes workspace files, manifests,
lock/config/toolchain files, exact crate-source files, stable/nightly sysroots,
rust-src/rust-lld, compiler/linker/LLVM tools, and their runtime dynamic
dependencies. Directory, glob, selected-source, version-only, and inherited
`PATH` authority is forbidden. If the literal ledger exceeds the 4096-record
contract bound, stop for schema review; do not replace it with an archive or
directory shorthand.

The production output is a private staging directory, not a Task 4 envelope.
It is produced before the receipt helper exists and introduces no build-subject
schema. It contains only the reviewed input ledger and these literal subjects:

- default `p11scope`, `p11scope-discover`, and raw eBPF object;
- small-ring `p11scope` and raw eBPF object;
- small-state `p11scope` and raw eBPF object;
- unsafe/freeze `p11scope`, `p11scope-discover`, and raw eBPF object;
- a Lane 09 matrix image archive.

Subject executables are mode 0700; ledgers, raw eBPF objects, and image archives
are mode 0600. The build gate records `build_head`, the ordered product-
affecting ledger digest, exact build argv/environment/toolchain identities, and
each subject's label, SHA-256, size, mode, and profile for independent review.

The Lane 09 archive has its own exact producer closure. Its base image is bound
by resolved digest/ID. The build is network-free and consumes either exact
local package bytes or an independently reviewed rootless OCI-builder subject.
Live `apt`, `apk`, mutable tags, and an undeclared Docker context are forbidden.

## Tracked authority and final-tip compatibility

After the production run, a tracked reviewed authority report is the opaque
build receipt. It records the private staging-root identity, every subject
identity, and the ordered product-affecting ledger digest; it is not parsed by
the Task 4 helper. Committing that report changes Git HEAD but not product bytes.
After all checker/helper/driver implementation and canonical checks, immediately
before Lane 07, a rootless final-tip compatibility verifier proves
that every product-affecting source, configuration, tool declaration, and
ledger member remains byte-identical to the build subject. A mismatch exits 77
and requires a fresh discovery review and production build. Unrelated planning,
checker, and evidence-report commits are allowed only when absent from the
product-affecting ledger.

Frozen or historical Lane 14 output cannot satisfy this gate.

## Consumer copy and validation

Each consumer blueprint declares the reviewed authority report as a retained
`tracked` input with its repository-relative locator. It declares the staging
input ledger and required subjects as literal `external-copied` inputs with
absolute locators. All are retained under `inputs/`. A consumer:

1. descriptor-relatively opens the private staging root and validates its
   directory identity, authority-report/ledger digests, and every expected
   subject SHA-256, size, mode, and profile;
2. copies required files with no symlink following into private caller-owned
   `nlink=1` retained inputs, fsyncs them, and revalidates source and copy;
3. never executes or hard-links from the upstream root;
4. runs no privilege, container, systemd, BPF, or lane resource before subject
   validation succeeds.

Each consumer contract—Lane 07, 09, 10, 11, 16-never, and 16-auto—adds a second
`CheckerDecl` named
`checker.laneXX.subjects`. It reuses the existing `checker.laneXX` input and
interpreter; it is not a fourth unresolved interface. Its fixed ABI is:

```text
CHECKER_INPUT subjects AUTHORITY_REPORT_INPUT LEDGER_INPUT
EXPECTED_REPORT_SHA EXPECTED_REPORT_SIZE EXPECTED_REPORT_MODE
PRODUCT_INPUT EXPECTED_SHA EXPECTED_SIZE EXPECTED_MODE ...
```

The exact expected values are contract literals. Before validation, the driver
opens every retained subject with `O_NOFOLLOW`, validates mode/dev/inode/size,
keeps those descriptors open, and expands the registered input tokens to those
exact `/proc/DRIVER_PID/fd/N` objects. It runs the exact registered argv
rootlessly before using a subject. It emits no output and creates no lane
resource. Product execution and image loading use those same still-open
descriptors, never a re-resolved retained path; close them only after the
consumer has established its separately tracked process/image ownership. Normal
final replay runs the identical argv again against the retained copies; that
replay is the sealed checker result. Replace-after-check, close-before-use, and
path-reopen mutations reject before privilege, Docker, systemd, or BPF. The lane-checker unresolved
interface therefore has two sorted bindings, `.domain` and `.subjects`, while
the blueprint still has exactly the lane checker, privacy scanner, and helper
unresolved records.

The helper validates only generic input custody. The lane checker validates the
subject ABI and expected identities. Lane 14 has no `.subjects` declaration or
binding because it remains source/build bound.

## Lane effects

- Lane 07 consumes four observer/eBPF profiles plus default and unsafe discover
  helpers. Its C fixtures remain lane-local builds with their smaller exact GCC
  closure.
- Lane 09 consumes the default observer and the sealed image archive. It
  validates archive bytes before `docker load`, records the loaded image ID,
  rejects an already-present image identity unless prior ownership is proven,
  and removes only an image created by this invocation. Two containers from
  that image preserve the shared-layer oracle.
- Lanes 10 and 11 consume default `p11scope` and `p11scope-discover`. Lane 11's
  sibling root, venv executables, package projection, state, policy, and cache
  invariants remain independent.
- Lane 16 consumes default `p11scope`; its hammer remains a lane-local GCC
  build. The accepted private-target/Cargo wording is replaced by exact retained
  subject identity. `never` and `auto` remain separate contracts.
- Lane 14 retains complete source, vendor, Cargo/eBPF/musl, image, package,
  Docker-context, distribution, and smoke input closure. Read-only source
  snapshots replace broad `$PWD:/src` authority.

`P11SCOPE_TASK4_PRODUCT` remains absent. Drivers use fixed root-relative copied
input paths and cannot accept caller-selected product directories.

## Blueprint privacy correction

Use one privacy checker per distinct scanner mode/exclusion, not one checker per
file. Each argv contains every matching artifact in bytewise path order. The
labels are:

- `checker.privacy.bytes` (including `stderr.log`, then `stdout.log`);
- `checker.privacy.json`;
- `checker.privacy.map-json`;
- `checker.privacy.trace-pid-tid-positions`;
- `checker.privacy.workload-log`;
- `checker.privacy.common.checker`, alone and last for `checker.log`.

Only labels used by a lane are declared. Lane 14 row 194 remains outside the
privacy groups: its domain checker invokes `map-json` and requires scanner
result 1. All 217 normalized Lane 14 crosswalk resource associations are exact
`ResourceDecl`s.

## Artifact-bound authority

The following exhaustive classes ratify the current fail-closed ceilings. Every
producer enforces its ceiling before registration and the helper enforces it at
acquisition and finalization. Nothing is truncated and observed output never
raises authority.

| Exact class | Count | Ceiling | Rationale |
|---|---:|---:|---|
| `**/*.txt` | 12 | 64 KiB | Fixed expected/status/head/tree text. |
| all `*.tsv` | 10 | 1 MiB | Complete canonical provenance ledgers under an operational cap. |
| structured/config/map/trace `*.json`, identity JSON, `*.conf`, `*.output` | 432 | 4 MiB | Bounded structured evidence; malformed or oversized input rejects. |
| `artifacts/oracle/report.jsonl` | 1 | 4 MiB | Fixed Lane 11 smoke output; complete or non-pass. |
| `artifacts/oracle/report-records.jsonl` | 1 | 4 MiB | Complete private cache serialization under the rules below. |
| `artifacts/distribution/p11scope-discover` | 1 | 4 MiB | Explicit release-helper cap. |
| all `*.log` | 52 | 8 MiB | Bounded-duration lane output. |
| `*.DISCOVERY.raw` and `*.EVENTS.raw` | 14 | 16 MiB | Complete retained ring streams. |
| `p11scope`, `p11scope-discover-glibc`, `p11scope-discover-musl` | 3 | 64 MiB | Explicit release-binary cap. |

The table covers exactly 526 artifacts in the rejected candidate; correction
must rederive exact coverage and counts after subject/product identity rows are
added.

Lane 11 accepts at most 4096 cache shards. Every entry is an owned, mode-0600,
`nlink=1` non-symlink regular file named `[0-9a-f]{64}.jsonl`; every other entry
rejects. Sort the complete set by full cache-relative path bytes, overflow-check
the raw-byte sum at 4 MiB, copy without separators or reserialization, and
record every path, identity, SHA-256, size, and contiguous `[start,end)` offset.
Canonical inventory records are at most 512 bytes and the inventory is at most
4 MiB. Missing/extra/reordered shards, directory mutation, hash mismatch,
offset gaps/overlap, and the 4097th shard reject.

## Revised gate order

1. Accept this decision and amend the governing plans.
2. Specify, RED-test, implement, and independently review the rootless
   build-subject discovery/production/compatibility gate.
3. Run the non-production discovery build, review and freeze its literal input
   ledger, then run one fresh production build-subject freeze.
4. Record and independently review the opaque tracked build authority.
5. Replace the rejected blueprint candidate with seven corrected,
   design-complete, non-executable blueprints; independently review them.
6. Continue the sealed-envelope interface RED, checker, helper, promotion, and
   serial driver-migration sequence.
7. After all canonical checks, rerun final-tip product-affecting compatibility
   immediately before Lane 07. Runtime lanes remain UNRUN until it passes.

The existing dirty observer/FD-5 Rust patch, historical receipts, and current
uncommitted blueprint candidate are not implementation authority.
