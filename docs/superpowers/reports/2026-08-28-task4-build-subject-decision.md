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

The current BS2a boundary implements only non-production candidate discovery.
`discover_input_v1` may consume a caller-supplied private trace, but its output
cannot authorize a build subject and has no production `expected` mode.
`produce` remains unavailable with exit 77.

Production authority begins only at the later integrated
`run_reconciled_build` boundary. That runner accepts no caller recipe, argv,
trace, PID, environment, classifier, or output name. It owns exact-object
preflight, the complete fixed build set, filesystem and network restriction,
trace launch/acquisition,
PID/start-time/nonce binding, complete descendant reap, reconciliation,
postflight revalidation, and private staging publication as one fail-closed
transaction.

The private interfaces are closed as follows:

```python
def discover_input_v1(
    trace: bytes,
    *,
    root_pid: int,
    initial_cwd: path,
    repo_root: path,
    vendor_relative: str,
    build_root: path,
    stable_sysroot_root: path,
    nightly_sysroot_root: path,
) -> bytes

def run_reconciled_build(
    *,
    expected_ledger_fd: int,
    repo_root: path,
    vendor_relative: str,
    stable_sysroot_root: path,
    nightly_sysroot_root: path,
    private_parent_fd: int,
) -> ProductionFreeze
```

`expected_ledger_fd` must name a held, caller-owned, mode-0600, `nlink=1`,
stable regular file. Its external rows declare reviewed classes only; the
runner independently derives every other field. One call runs the closed
default, small-ring, small-state, and unsafe/freeze Cargo recipes and the sealed
Lane 09 image producer, then returns the complete staging set or nothing.
Commands, environment, target names, output names, trace location, and process
identity are internal constants, never caller inputs.

`private_parent_fd` must be a held, fsync-capable
`O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW` descriptor for a caller-owned
mode-0700 directory. Its device, inode, uid, gid, and mode remain stable. The
runner records the initial descriptor-relative listing, creates nonce-named
build, trace, and pending-staging children, and holds every created directory.
The final-staging name must remain absent until pending staging is published
with `renameat2(RENAME_NOREPLACE)`. Produced files, created directories, and the
parent are fsynced. Final validation permits exactly the new held final-staging
entry and its entailed parent link-count/time changes; every initial entry is
unchanged and every other created identity is absent. The runner removes only
identities it created. A collision, replacement, link, unexpected namespace
delta, ownership/mode mismatch, fsync failure, or cleanup uncertainty is
non-pass.

Cargo is locked and offline. The ledger includes workspace files, manifests,
lock/config/toolchain files, exact crate-source files, stable/nightly sysroots,
rust-src/rust-lld, compiler/linker/LLVM tools, and their runtime dynamic
dependencies. Directory, glob, selected-source, version-only, and inherited
`PATH` authority is forbidden. If the literal ledger exceeds the 4096-record
contract bound, stop for schema review; do not replace it with an archive or
directory shorthand.

The private literal ledger is canonical LF-terminated UTF-8 TSV named
`input-v1`. It is not a Task 4 envelope or public-evidence schema. It contains
1..4096 rows and at most 4 MiB. Every row has exactly nine fields:

```text
input-v1<TAB>SEQ<TAB>CLASS<TAB>ACCESS<TAB>RESULT<TAB>MODE<TAB>SIZE<TAB>SHA256<TAB>LOCATOR<LF>
```

The file contains no blank row, CR, NUL, BOM, or trailing bytes, and ends in
exactly one LF. `SEQ` is `0|[1-9][0-9]*`, equals the row's zero-based position,
and is at most 4095. There is exactly one row per `LOCATOR`. Rows are in strict
ascending order of the complete locator's raw UTF-8 bytes; repeated observations
of one locator are combined before sorting. A lone regular-file metadata or
open-only observation produces `probe`; an actual `read` or `mmap` upgrades it
to `read`, an actual `exec` upgrades it to `execute`, and observing both actual
accesses produces `read-execute`. A lone directory metadata observation
produces `probe`; `enumerate` subsumes it. Conflicting classes, results,
identities, or contents reject as mutation.

`LOCATOR` is 1..4096 UTF-8 bytes and has exactly one of these disjoint forms:

```text
repo:/
repo:/COMPONENT(/COMPONENT)*
vendor:/
vendor:/COMPONENT(/COMPONENT)*
external:/
external:/COMPONENT(/COMPONENT)*
```

`repo:/` is anchored at the exact `build_head` checkout, and `external:/` at
filesystem root. The vendor anchor is a reviewed canonical relative path opened
descriptor-relatively beneath the held repo anchor. An equal, outside,
symlink-escaped, or independently opened vendor root rejects. A path at or
beneath the vendor anchor must use `vendor:`; a path beneath either private
anchor cannot use `external:`. A component is 1..255 raw UTF-8 bytes, is neither
`.` nor `..`, contains no `/`, NUL, Unicode `Cc`, `Cf`, or `Cs` code point, and
is not Unicode-normalized or case-folded: its original UTF-8 bytes are
authoritative. Repeated separators and a trailing separator except in the three
root locators reject. Path-bearing syscall paths are resolved immediately from
the traced process's held exact cwd or held dirfd (absolute paths start at the
held filesystem root). Resolution is a raw kernel-order descriptor-relative
walk, not `realpath`: `.` is consumed as reached; `..` is applied only when
reached, and a symlink's raw target components are prepended to the pending
walk. Relative targets resume at the held symlink parent and
absolute targets at the held filesystem root. Inability to resolve the exact
cwd, dirfd, or path rejects.

### Custody identity roles

Custody-only relations are weaker than evidence rows. The filesystem root `/`,
the traced process's exact `cwd`, every dirfd used as a path start, every
observation or absence start, every intermediate ancestor, each supplied
`repo`, `build`, `stable`, `nightly`, or `vendor` anchor, and every parent of a
created output are acquired once as held nodes. Their one-attempt acquisition
and final parent/name plus held-FD binding use only the structural identity
`(st_dev,st_ino,S_IFMT(st_mode))`. A mismatch is an immediate mutation
failure: acquisition is never retried, reopened, or accepted from a
replacement. Unrelated unobserved child creation or removal beneath a held
ancestor is not evidence and does not invalidate that binding. A logical
final-leaf output under the initially empty held build root has no physical
node and emits no input.

Retained relations are cached only by the held parent relation plus raw name;
no textual path or locator cache may reopen or restart a relation from `/`.

Full nine-field identity `(st_dev,st_ino,uid,gid,st_mode,st_nlink,st_size,
st_mtime,st_ctime)` is captured by the first evidence role at event time and
continues through final validation only for retained regular inputs, ENOTDIR
blockers, observed symlinks, and emitted directory rows, including the ENOENT
parent row. An anchor is held to the full nine fields only when it is itself
evidenced by one of those rows; otherwise it remains structural-only.

The owned build root has a direct descriptor-relative exact-emptiness check at
both initial setup and final validation, reusing the held-FD `os.listdir`
operation. Its emptiness is never inferred from timestamps or another
directory metadata proxy. Created-output parents remain held nodes; a logical
final leaf has no physical node and is never emitted as input.

`CLASS`, `ACCESS`, `RESULT`, and the value fields obey this exhaustive matrix:

| `CLASS` | Locator namespace | `ACCESS` | `RESULT` | `MODE`, `SIZE`, `SHA256` |
|---|---|---|---|---|
| `repo` | `repo:` | `probe|read|execute|read-execute` | `present` | Present regular-file values |
| `vendor` | `vendor:` | `probe|read|execute|read-execute` | `present` | Present regular-file values |
| `stable-sysroot|nightly-sysroot|tool|dynamic` | `external:` | `probe|read|execute|read-execute` | `present` | Present regular-file values |
| `host-config|lane09-base|lane09-package` | `external:` | `probe|read` | `present` | Present regular-file values |
| `directory` | any namespace | `probe|enumerate` | `present` | Directory-listing values |
| `symlink` | any namespace | `probe` | `present` | Symlink-target values |
| `absent` | any namespace | `probe` | `ENOENT|ENOTDIR` | `-`, `-`, `-` |

No other combination is valid. `repo` and `vendor` are selected by locator
namespace. External regular files below the two exact, disjoint pinned sysroot
roots use the corresponding sysroot class; the exact reviewed Lane 09 base
archive and package-byte sets use `lane09-base` and `lane09-package`;
predeclared configuration files use `host-config`; loader/interpreter/shared-
library inputs outside those sets use `dynamic`; every remaining external
regular build input uses `tool`. Overlapping external classifications reject.
A `lane09-base` row always names exact local regular archive bytes; its resolved
OCI digest/ID remains in the already-required opaque build authority and is not
encoded as a fake path.

For a present regular file, `MODE` is exactly four lowercase octal digits for
`st_mode & 07777`, `SIZE` is canonical unsigned decimal in `0..4294967296`,
and `SHA256` is exactly 64 lowercase hexadecimal characters over the complete
file bytes. Collection and verification use a held `O_NOFOLLOW` regular-file
descriptor, stream the hash, and require unchanged device, inode, uid, gid,
mode, link count, size, mtime, and ctime across the read. Hard links are
permitted but distinct locators remain distinct rows.

The external post-S2 scheduling case remains `FORMAL_REVIEW_ONLY`: independent
line review must prove the retained-FD metadata/hash sequence and final
parent/name binding, but no racy oracle is promoted to executable acceptance.

A directory row never grants authority to read or execute a descendant and
never replaces a literal row for a consumed descendant. Its hash preimage is
the complete immediate directory listing, excluding `.` and `..`. Each entry
is encoded as one type byte (`F` regular, `D` directory, or `L` symlink),
followed by the entry-name byte length as unsigned big-endian 16-bit, followed
by the raw name bytes. Entries are sorted strictly by raw name bytes and
concatenated without a header or terminator. Names are 1..255 bytes; duplicate
names, any other file type, more than 4096 entries, or a listing exceeding
4 MiB reject. `MODE` is the held directory's four-octal-digit mode, `SIZE` is
the canonical decimal preimage length, and `SHA256` hashes that exact preimage.
Two descriptor-relative listings and the directory's before/after device,
inode, uid, gid, mode, link count, size, mtime, and ctime must agree; otherwise
collection or verification rejects as mutation. Raw listing names are never
retained.

Every symlink component encountered while resolving a consumed or probed path
has its own row. `MODE` is the symlink's four-octal-digit `lstat` mode, `SIZE`
is the canonical decimal length in `1..4096` of the exact raw `readlinkat`
target bytes, and `SHA256` hashes those bytes. The target bytes are read twice;
the symlink's before/after device, inode, uid, gid, mode, link count, size,
mtime, and ctime must agree. Relative targets resolve from the held symlink's
parent; absolute targets resolve from the held filesystem root. Raw target
components are prepended to the pending walk, with `.` and `..` consumed only
when reached. Namespace selection after resolution is vendor, then repo, then
external according to the two anchors above. Every resolved target locator must
have its own `symlink`, `directory`, present-regular, or `absent` row. Every
link in a chain is recorded; 40 total follows are allowed and the 41st
rejects, with no repeated-locator rejection. An unencodable resolved locator or
a special-file target rejects. Raw target bytes are never retained.

An absent row names the canonical requested locator after resolving every
existing prefix. Its retained internal evidence includes the held start node,
raw syscall path, errno, canonical resolved locator, and full missing/blocking
boundary identity; these do not add fields to the public nine-field row.
`ENOENT` requires a `directory` row for the nearest existing parent and rows
for every traversed symlink; `ENOTDIR` requires a present row for the first
blocking non-directory component and rows for every traversed symlink. An
unresolved suffix has a floor at the missing or blocking component: raw
`name` and `..` steps are permitted only above that floor; crossing it or
collapsing to the blocker rejects. Raw absence replay is the last filesystem
observation; production must reproduce the exact errno, canonical resolved
locator, and held boundary identity with a live boundary validation. Any
mismatch is non-pass and is never repaired by retrying acquisition. `EACCES`,
`ELOOP`, unknown results, unresolved dirfds/cwds, and all other failures stop
discovery for schema review rather than being ignored or generalized.

Finalization order is fixed: collect/hash/list -> final build list -> full
bindings -> raw absence replay/boundary -> pure encode -> finally close all
held descriptors. Pure encoding performs no filesystem access.

The discovery trace must classify every successful regular-file read, mapping,
or execution, every product-affecting metadata probe, every directory
enumeration, and every `ENOENT` or `ENOTDIR` probe across all traced processes.
Every path-bearing event is resolved immediately from its held cwd/dirfd by the
raw kernel-order walk above. A path first created inside the owned clean build
root is an internal output, not an `input-v1` row; its logical final leaf has
no physical node and emits no input, while its created parent is held.
Preexistence, read before owned creation, or use of an unowned generated path
rejects. Production must observe no additional literal input or probe and must
reproduce every ledger row. Directory hashes grant no directory read authority;
the sandbox authorizes only the literal resolved objects required by the
reviewed rows.

Before production launch, every reviewed present, symlink, directory, and
absent relation is independently reproduced. Present regular inputs remain
held with `nlink>=1`; distinct hard-link locators remain distinct rows. Landlock
grants read or execute rights to exact held regular-file objects and `READ_DIR`
only to reviewed directory rows. No repo, vendor, sysroot, tool parent, or
filesystem root receives recursive read authority. The initially empty owned
build root is the only broader filesystem rule.

The production runner acquires the complete private trace itself and binds it
to its child by PID, kernel start time, nonce handshake, parentage, and reap
status. Caller-supplied trace bytes or process identities never satisfy
production. Every held object and locator relation is revalidated after all
descendants exit. Any mutation, missing or extra operation, incomplete trace,
restriction failure, network capability, or surviving child is non-pass.

Before launch the runner closes every inherited descriptor except its own
private pipes and held authority descriptors. The complete producer tree enters
fresh rootless user, mount, PID, and network namespaces with a private `/proc`;
the network namespace has no configured interface. The trusted trace supervisor
and every build/image helper are owned descendants in that boundary. Builds use
`PTRACE_TRACEME`/parent tracing and are not attachable by peers. Build children
cannot name a host process and an inherited seccomp filter rejects `socket`,
`connect`, `sendto`, `sendmmsg`, `io_uring_setup`, `pidfd_getfd`, `ptrace`,
`process_vm_readv`, and `process_vm_writev`; local `socketpair` IPC may remain.
The trace supervisor has the same network/FD-theft filter but retains only the
minimum descendant-`ptrace` operations needed to collect the owned trace. A
trusted launcher requests `PTRACE_TRACEME` before stacking the tracee's inherited
deny-`ptrace` filter, and the supervisor confirms the initial stop before exec.
A Landlock network ruleset grants no TCP bind/connect right. The outer
orchestrator executes no ledger-controlled byte and has the same network and
FD-theft denials before supervising the isolated tree. An external OCI daemon,
daemon socket, host `/proc`, surviving helper, or process outside these controls
cannot satisfy production. If the host or fixed producer cannot establish and
retain every boundary, BS2b exits 77 before publication; postflight trace
comparison is not a network control.

Encoding uses the closed spellings above, canonical decimal/octal forms, and no
escaping. Parsing followed by canonical encoding must reproduce the exact input
bytes. Any syntax, matrix, ordering, namespace, bound, filesystem, relation, or
round-trip failure rejects. The candidate trace and ledger remain mode-0600
private inputs; only their ordered digest and already-approved opaque identities
enter tracked authority. No locator, raw directory listing, or raw symlink
target enters tracked or public evidence.

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
by resolved digest/ID. The build is network-free and consumes exact local
package bytes through an independently reviewed daemonless rootless OCI-builder
subject running as an owned filtered descendant. Live `apt`, `apk`, mutable
tags, external daemons/sockets, and an undeclared Docker context are forbidden.

## Stage3 authority amendment (2026-08-30; accepted)

**Status:** the accepted baseline and independently reviewed RAW SYMLINK 40/41
clarification below are governing.

This amendment is the controlling BS2b capacity, ordering, and raw-symlink
authority for staged Stage3 work. It changes no product contract, privacy
allowlist, schema, or schema row limit.

### CAPACITY

BS2b acquires every graph/scan FD exactly once and retains it. It does not batch
acquisition, drop and reopen descriptors, retry acquisition, raise
`RLIMIT_NOFILE`, sweep FDs, precount, or use a prefix estimate. Before graph
acquisition it records exactly one finite, nonnegative, exact-integer
`RLIMIT_NOFILE` tuple `(soft, hard)`, with `soft <= hard`.

An exact `EMFILE` from a specified graph/scan open triggers exactly one
immediate reread of that tuple. Only an unchanged tuple may stop dependent
acquisition. The runner then performs safe final private-plus-borrowed custody
and bindings for held nodes, skips the canonical absence caused by the
incomplete graph, and reverse-closes exactly once. Silent exit 77 is permitted
only after the exact checks and cleanup. `ENFILE`, an invalid or colliding
descriptor, drift, any other post-baseline failure, or cleanup uncertainty is
`MutationError`.

A syntax-valid ledger may be capacity-refused; capacity refusal does not imply
batching or a product row cap. Native capability constants are exact:
`O_RDONLY == 0`; `O_CLOEXEC`, `O_NOFOLLOW`, and `O_DIRECTORY` are exact
positive values whose required open-flag bits do not collide; `FD_CLOEXEC` is
exactly positive; `O_PATH` must be exactly positive when the ledger contains a
symlink row and is not required otherwise; and `F_GETFD` is exactly
nonnegative. Missing native support is a stable refusal before graph
acquisition. Present zero, wrong-type, or colliding security flags are
`MutationError`. After graph acquisition begins, only an exact unchanged-tuple
`EMFILE` may be a stable refusal.

### ORDER

BS2b's order is exact: preflight the exact held graph; establish private-parent
transaction custody and an initially-empty held nonce build root; construct the
complete literal Landlock ruleset from the inputs and build root; then establish
the producer/isolation boundary and apply enforcement before exec. Preflight
alone does not authorize a child. Ruleset construction is not enforcement;
`no_new_privs` plus `restrict_self` in the intended child is enforcement.

### RAW SYMLINK

Raw symlink target bytes are ephemeral. They are not decoded, normalized,
logged, cached, or published. Each symlink occurrence admitted to follow (the
first through fortieth) is held with `O_PATH|O_CLOEXEC|O_NOFOLLOW` and performs
exactly two descriptor-relative `readlink` calls bracketed by stable full
identity. A repeated locator is a fresh occurrence and never reuses target
evidence. Target closure is resolved immediately after the second read before
the bytes are discarded; the held symlink descriptor remains owned through
final binding and cleanup. The refused forty-first occurrence is opened and
fully validated by the initial held-FD then parent/name no-follow identity
bracket, then raises `MutationError` before its first `readlink`, target
closure, or any later filesystem observation; ordinary governed cleanup still
runs. An empty target rejects. Repeated slashes collapse; absolute targets
start at the held root, relative targets at the held link parent, `.` is a
no-op, and `..` clamps held parents at the root. A trailing slash requires a
directory. Target components are processed before the remaining original
components. Every encountered link and final relation has a ledger row. No
text reopen or repeated-locator shortcut is permitted.

This amendment authorizes only staged `3A0`-`3A3` RED/GREEN/review after these
docs are accepted. It does not authorize a build, child/build-root creation,
Landlock implementation or probe, producer, runtime, publication, or release.
Stage3 code remains gated until independent review and commit. The privacy
allowlist and schema row limits remain unchanged.

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
