# Task 4 Remaining-Lane Receipt Closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `superpowers:subagent-driven-development` to implement this plan task by task.
> Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the remaining production Task 4 lanes emit private,
source-bound, terminal evidence without changing their product oracles, then
run exactly once and serially: 07, 09, 10, 11, 14, Lane 16 `never`, Lane 16
`auto`.

**Architecture:** Keep evidence ownership inside each lane because only the
lane can bind ephemeral container, process, cgroup, and build identities before
cleanup destroys them. Reuse existing shell and Python oracles; add no generic
controller, receipt library, public schema, or product behavior. Every modified
normal driver consumes one absent private evidence root and owns one terminal
status; the Lane 14 nested discover script owns facts only.

**Tech Stack:** POSIX shell, existing Python 3/JQ oracles, Rust 1.88 edition
2024 artifact contracts, Linux x86-64, `flock`, Docker/systemd/eBPF only in the
later authorized runtime stage.

**Spec:**
`docs/superpowers/plans/2026-08-25-slice1b2-next-gates.md` Task 4,
`docs/superpowers/plans/2026-08-19-slice1b2-production.md` owned-run
cardinalities, and `docs/superpowers/plans/ROADMAP.md` topology ruling.

## Global constraints

- Preserve `docs/privacy/allowlist-v1.md`; do not broaden capture or public
  evidence vocabulary.
- Preserve Rust 1.88, edition 2024, and Linux x86-64-first support.
- Modify no product Rust/BPF, Cargo manifest/lock/config/toolchain, schema,
  checker, common shell library, cleanup helper, README, or public usage file.
- Run at most one Cargo-heavy command at a time.
- Runtime lanes stay `UNRUN` until this plan is reviewed, committed,
  implemented, verified, independently reviewed, and committed.
- Run each production lane once. There is no automatic retry, resume, evidence
  replacement, or inference of PASS from an absent receipt.
- Sol xhigh architecture/correctness review is mandatory. Per the user's
  requested important-decision policy, focused Terra and Luna reviews must also
  agree before the plan and implementation gates advance.

---

## Frozen baseline and Lane 02 disposition

The required fresh production Task 4 sequence already began with Lane 02 at
source HEAD `91e21496ae4e7d151c050a9dee2e8547d2d6cb75`, tree
`ecc619edc63194599328fc1ad926c301da717e0e`. The single production root is:

```text
/home/user/.local/state/p11scope/task4-500ms-20260827/lane02
```

Its `facts.log` is mode 0600, device/inode `43:16617428`, and SHA-256:

```text
03d39635a879ae5d3dcc22a6689f579c5a0d6644f68051fdd21cbfb587e255d8
```

It contains exactly six invocations and terminal status zero. It remains the
Lane 02 result in this same Task 4 board at its recorded HEAD; it is never
relabelled as final-HEAD or CI evidence.

Before any later runtime lane, write a compatibility report beneath the common
campaign parent that records both HEADs and proves mechanically that the final
receipt-only diff changes none of:

- `scripts/verify-task4-lane02.sh`, `scripts/check-capture-evidence.py`,
  `scripts/lib.sh`, `scripts/cleanup-traps.sh`, `spike/harness.c`, or
  `spike/expected.txt`;
- product Rust/BPF, `build.rs`, Cargo manifests/locks/config/toolchains; or
- any file whose bytes contributed to the recorded `p11scope`, harness,
  provider, config, or Cargo-configuration identities.

The compatibility report must rehash the immutable Lane 02 facts file and
validate the six exact tuples `(initial-set|dlopen) × (never|auto|always)`.
Every row retains `68/68/136`, the exact positive counts from
`spike/expected.txt` plus one `C_GetFunctionList`, exactly one authorized
sanitized timing projection, and zero required loss/ambiguity/in-flight
counters. `never` retains `none/0/0/0`; `auto|always` retains `sigstop` with
attempts equal confirmed and at least one, partial zero. Any overlap or mismatch
invalidates compatibility and requires new reviewed authority. It does **not** authorize an
automatic Lane 02 rerun: another run would create twelve Task 4 attempts and
contradict the exact-six cardinality.

## Exact receipt interface

### Normal drivers

The six normal entry points are literal:

```sh
sh scripts/verify-induced-gaps.sh ABSENT_ABSOLUTE_ROOT
sh scripts/matrix/verify-shared-layer.sh ABSENT_ABSOLUTE_ROOT
sh scripts/matrix/verify-fork-scope.sh ABSENT_ABSOLUTE_ROOT
sh scripts/matrix/verify-oracle.sh ABSENT_ABSOLUTE_ROOT
sh scripts/build-release.sh ABSENT_ABSOLUTE_ROOT
sh scripts/verify-task4-lane16.sh ABSENT_ABSOLUTE_ROOT never
sh scripts/verify-task4-lane16.sh ABSENT_ABSOLUTE_ROOT auto
```

Every modified/new normal driver also accepts exactly:

```sh
sh SCRIPT --self-test
```

The evidence root must be an absent absolute path outside the worktree. Its
canonical parent must already exist, be caller-owned mode 0700, and have no
symlink component. After atomic ownership checks, the driver creates the root
mode 0700 and uses this fixed layout:

```text
ROOT/
  facts.log
  stdout.log
  stderr.log
  artifacts/
  work/
  status
```

Regular evidence/configuration files are 0600. Private binaries in `work/` are
caller-owned mode 0700 only while executed; their retained copies and all other
non-executed artifacts are 0600. `status` is a single decimal line and is written
exactly once as the final filesystem operation: `0` means receipt and lane
oracle PASS, `77` means prerequisite/infrastructure `UNRUN` before product
consumption, and every other value is `NON-PASS`. Invalid root authority
returns 77 without touching the path. A prerequisite failure after root
creation may retain preflight facts plus final status 77, but may not create a
product capture or owned runtime resource.

Set `CAMPAIGN=$(dirname -- "$ROOT")` only after the root parent has been
canonicalized and validated; it is that caller-owned mode-0700 parent, not an
environment override. Every normal driver opens the same
`$CAMPAIGN/.task4.lock`, mode 0600, and takes a
nonblocking exclusive `flock` before inspecting or mutating shared Cargo,
Docker, systemd, cgroup, or target state. It holds the lock through terminal
status. The receipt records the lock dev/inode and holder PID/starttime. This is
one common overlap guard, not a receipt framework.

Create `artifacts/` and `work/` as caller-owned mode-0700 directories and
record/revalidate their device/inode identities. No other top-level directory
is allowed.

### Lane 14 nested facts

`build-release.sh` alone owns the Lane 14 root and terminal status. Its exact
nested call is:

```sh
sh scripts/verify-discover-containers.sh \
  --lane14-facts "$ROOT/artifacts/discover.facts"
```

The child accepts only that option or `--self-test`. It requires an absent
regular-file path directly beneath the already-validated Lane 14 `artifacts/`
directory, creates it mode 0600, records facts but no terminal status, and
returns nonzero on any cleanup or identity uncertainty. `build-release.sh`
immediately opens the child facts with `O_NOFOLLOW` after the synchronous child
returns, compares `fstat` dev/inode/owner/mode with the identity recorded inside
the facts file, hashes through that descriptor, and retains the descriptor
through finalization. It includes that hash in Lane 14 finalization; any missing,
replaced, malformed, or multiply linked facts object is nonzero.

## Receipt lifecycle and provenance contract

After root creation, each normal driver installs one finalizer covering every
exit path. The finalizer performs, in order:

1. retain the body/oracle result without printing a lane PASS;
2. clean only resources whose immutable identities were recorded and synced;
3. query and prove absence of every owned resource;
4. revalidate the evidence root, every mutable input, source HEAD/tree, tracked
   cleanliness, and all recorded hashes;
5. reject foreign or missing terminal artifacts and validate the allowed tree;
6. upgrade a zero body result to nonzero on cleanup/query/input uncertainty;
7. `sync` retained facts/artifacts; and
8. write exactly one `$ROOT/status` line last and return that value.

Existing `ALL OK` text is emitted only after finalization or renamed `body
oracle OK`; the decimal terminal status is the sole lane verdict.

Every receipt records start/end UTC, literal argv, cwd, uid/gid, kernel, HEAD,
tree, tracked cleanliness, source/input start and end ledgers, and:

- root and eBPF Cargo locks, `build.rs`, Cargo configs, eBPF toolchain file;
- stable/nightly `cargo` and `rustc`, sysroot, rust-src, rust-lld, clang/LLVM,
  linker, compiler, Docker/systemd/bpftool versions when consumed;
- cleared or recorded build-affecting environment, including all induced-gap
  feature variables;
- provider realpath/dev/inode/mode/owner/size/SHA-256/build ID;
- exact actual observer, discover helper, workload, checker, and BPF object
  dev/inode/size/SHA-256 before use and again at finalization; and
- exact Docker base/image/container IDs and available digests, process
  PID/starttime/session, systemd invocation/unit, and cgroup identity.

Mutable regular files are opened first and hashed/stat'ed through
`/proc/$$/fd/N`; the same descriptor is used or copied into private `work/`
before consumption. Pathname-only rehashing is insufficient. Docker cleanup
targets the recorded container/image ID, never a reusable name or tag. Process
cleanup uses PID plus starttime/pidfd verification. Cgroup/systemd cleanup uses
the exact recorded invocation identity and path. Identity mismatch prevents
destructive cleanup, makes the receipt nonzero, and retains diagnostic facts.

Tracked source must be clean using `git diff --quiet` and
`git diff --cached --quiet`; HEAD/tree recording uses
`--untracked-files=no`. Untracked files are never executed or build/Docker
inputs. Reject an untracked path within any consumed Cargo or Docker context.
A reviewed non-input exception outside those contexts is allowed only when its
path and SHA-256 are recorded; the existing OpenSSL feasibility report is such
an exception. The separately committed receipt plan is not untracked during
implementation/runtime.

## Lane contract matrix

### Lane 07 — induced gaps

**Driver:** `scripts/verify-induced-gaps.sh`.

**Prerequisites before consumption:** `gcc`, SoftHSM2, Python 3, Rust 1.88,
nightly/eBPF LLVM toolchain, `bpftool`, `systemd-run`, `sudo -n`, provider, and
the existing dump-helper self-test. If the current second-DISCOVERY-ringbuf
`dump-owned-bpf-maps.py`/`bpftool` path cannot inspect the owned maps (including
the known rc 244 class), finalize 77 before the six production cases.

**Artifacts/oracle:** retain fixture/provider/BPF identities, before/after map
inventories and dumps, cgroup and PID/starttime identities, and every capture,
manifest, checker log, and exit for freeze plus G1 aliasing, G2 in-flight, G3
event loss, G4 START loss, and G5 RV loss. Preserve the existing freeze and
G1–G5 oracle byte-for-byte. Its literal shapes are G1 `160/93/186`, G2
`68/2/4`, G3 `68/68/136`, and G4/G5 `988/104/208` for
`table_entries/slots/attached_probes`. G3 retains exact positive calls
`C_GetFunctionList=1`, `C_Initialize=1`, `C_Finalize=1`, `C_GetSlotList=1`,
`C_OpenSession=1`, `C_CloseSession=1`, `C_GenerateRandom=200000`; G4 retains
`in_flight_at_end=9` and `start_insert_failures=8`; G5 retains 11 calls,
`rv_update_failures=9`, `unregistered_mechanisms=6`, and `async_orphans=1`.
The freeze control requires the existing exact eight-map inventory: `CONFIG`,
`PID_FILTER`, `CGROUP_FILTER`, `DESCRIPTORS`, `ASYNC_FUNCTIONS`, `MECH_SHAPE`,
`ATTR_BOOL_BITS`, and `TEMPLATE_TAIL`. Final absence covers observer/workload
processes, cgroup/unit, and owned BPF objects.

### Lane 09 — shared Docker layer

**Driver:** `scripts/matrix/verify-shared-layer.sh`.

**Prerequisites before consumption:** Docker client/daemon/storage, `gcc`,
SoftHSM2, Python 3, Rust 1.88, `sudo -n`, resolved base image, and writable
private evidence work. This receipt plan supersedes the earlier Lane 09 UNRUN
status only after its implementation commit passes review.

**Artifacts/oracle:** put all disposable work under `$ROOT/work`; retain Docker
client/server/storage facts, requested and resolved base, built image ID/digest,
both container IDs and process generations, provider content/build identity and
both filesystem views, broad and leaf cgroups, product/harness identities, and
three captures/checker logs. Preserve exactly: broad sees two workloads and one
uncertainty; `a-only` and `b-only` each see one workload and zero uncertainty.
Each capture is `68/68/136`; broad positive function counts are exactly twice
`spike/expected.txt` plus `C_GetFunctionList=2`, while each leaf is exactly the
file plus `C_GetFunctionList=1`. Prove exact container IDs, image ID, processes,
and cgroups absent.

### Lane 10 — fork scope and capability relationships

**Driver:** `scripts/matrix/verify-fork-scope.sh`.

**Prerequisites before consumption:** cgroup v2, systemd, `capsh`, tracefs/DAC
context, `gcc`, SoftHSM2, Python 3, Rust 1.88, provider, and `sudo -n`. If the
intended capability row cannot be formed because tracefs or DAC infrastructure
is unavailable, finalize 77 before its capture rather than fabricating a
relationship.

**Artifacts/oracle:** retain product/discover/provider/harness/manifest/expected
identities, one fork row and exact-count result, and exactly four measured
capability rows with literal capability sets, status, documents, and logs.
The fork row is `68/68/136`, with exact positive counts from
`scripts/matrix/fork-expected.txt`: `C_CloseSession=4`, `C_Digest=20`,
`C_DigestInit=20`, `C_Finalize=5`, `C_GetInfo=1`, `C_GetSlotList=4`,
`C_Initialize=5`, and `C_OpenSession=4`, plus the existing manifest-only
`C_GetFunctionList` bootstrap relation.
Retain ptrace/perf/tracefs context and the measured
`scan_unavailable`/`discovery_uncorroborated` relationship. Preserve the current
`terminal_capture_is_clean(..., uncorroborated=1)` assertion unchanged. Only a
fresh otherwise-valid mismatch may authorize a later, separately reviewed
oracle amendment; recording the measured relationship does not itself amend or
supersede that candidate hard-coded assertion. Prove target processes,
cgroup/unit, and FIFO absent.

### Lane 11 — independent pkcs11-check oracle

**Driver:** `scripts/matrix/verify-oracle.sh`.

**Prerequisites before consumption:** exact sibling
`/home/user/src/m/pkcs11-check-ws/pkcs11-check`, its executable `.venv`, cgroup
v2/systemd, SoftHSM2, Python 3, Rust 1.88, provider, and `sudo -n`. Both sibling
`.pkcs11-check-isolation-state.json` and
`.pkcs11-check-isolation-state-policy.json` must be absent initially; otherwise
finalize 77 and never delete them.

**Artifacts/oracle:** use
`cargo +1.88 build --locked --release --workspace`. Retain equal start/end
sibling HEAD/tree/tracked-clean ledgers, lock/project/venv file identities,
installed-package projection, state-file absence, provider/product/BPF
identities, raw oracle reports, manifest/capture/log, and derived subset
summary. Remove only isolation files proven to have been created by this
invocation, after regular-file/dev/inode/owner validation; require both absent
at finalization. Any sibling, venv, package, or state-ledger mutation invalidates
the lane. Preserve the current subset and terminal-capture oracles; current
aggregate totals are not frozen acceptance counts.

### Lane 14 — release build

**Driver:** `scripts/build-release.sh`; nested facts producer:
`scripts/verify-discover-containers.sh`.

**Prerequisites before consumption:** `file`, `jq`, `setpriv`, Python 3,
Rust 1.88 stable and required nightly/eBPF toolchain, musl target and linker,
`gcc`, Docker client/daemon, `sudo -n`, SoftHSM2, resolved build images, and the
dump-helper/bpftool path used by nested gates. If the known second-DISCOVERY
ringbuf inspection cannot run, finalize 77 before consuming release evidence.
This plan supersedes the earlier Lane 14 UNRUN status only after implementation
review.

**Artifacts/oracle:** put mutable build/dist work beneath `$ROOT/work`; retain
all nested script/checker hashes, toolchain/target/vendor/config inputs,
official observer/BPF and final distribution inventory, canary/e2e/static-smoke
evidence, three resolved build-image IDs/digests and package projections,
nested container IDs, and the bound nested facts file. Preserve every existing
release oracle. The final inventory is exactly four executables:
`p11scope`, `p11scope-discover`, `p11scope-discover-glibc`, and
`p11scope-discover-musl`; `p11scope` is static musl and rejects the unsafe flag,
the two glibc names are byte-identical, and the musl helper is dynamically
linked. Ubuntu glibc, Alpine musl, packaged-helper, and host helper smokes each
retain 68 SoftHSM records; the deterministic fixture retains the exact
68/92/104 table shapes; the packaged static attach smoke retains
`68/68/136` and exact `spike/expected.txt` plus one `C_GetFunctionList`.
Prove containers, images owned by ID, target processes, and observer absent.
`build-release.sh` is the only terminal owner.

### Lane 16 — two fixed structural rows

**Driver:** new `scripts/verify-task4-lane16.sh`.

**Prerequisites before consumption:** `gcc`, `sudo -n`, SoftHSM2, Python 3,
Rust 1.88, provider, `scripts/fixtures/hammer.c`, and
`scripts/check-capture-evidence.py`. Missing current-head binary inputs,
checker, compiler/toolchain, provider, or `sudo -n` finalizes 77 before build or
capture. Reject inherited build-affecting Cargo/Rust/compiler environment using
the same fixed list as Lane 02.

**Build/config:** create `$ROOT/work/tokens` mode 0700 and
`$ROOT/work/softhsm2.conf` mode 0600, initialize one private SoftHSM token, and
record/revalidate both. Build only with:

```sh
CARGO_TARGET_DIR="$ROOT/work/target" \
  cargo +1.88 build --locked --release --workspace
gcc -O0 -o "$ROOT/work/hammer" scripts/fixtures/hammer.c -ldl
```

The observer is exactly `$ROOT/work/target/release/p11scope`; a bare
`p11scope`, PATH lookup, unpinned/unlocked Cargo build, or observer outside that
private target is invalid. Record/revalidate the observer's
dev/inode/size/SHA-256 and every Cargo/source input.

**Workload:** validate `MODE` by `case "$MODE" in never|auto) ;; *) exit 2 ;;
esac`, then run exactly one requested row through the existing verified-root
launcher with the literal product shape and a clean environment:

```sh
/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
  SOFTHSM2_CONF="$ROOT/work/softhsm2.conf" \
  "$ROOT/work/target/release/p11scope" run \
  --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so \
  --mode metrics --duration 30 --kill-on-timeout --pause "$MODE" \
  -o "$ROOT/artifacts/observed.json" -- \
  "$ROOT/work/hammer" \
  /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so 200000
```

The driver contains one fixed-arity gate-only validator; it is not a new public
checker or product PASS framework. Each of the separate `never` and `auto`
invocations must independently exit zero and require exactly the complete
authoritative predicate list:

- 68 table entries, 68 slots, and 136/136 entry/return probes;
- exactly one authorized sanitized
  `{"name":"discovery subject","reason":"discovery unavailable"}` timing
  projection;
- `event_loss == 0`; `discovery_ring_loss == 0`,
  `discovery_state_failures == 0`, `discovery_read_failures == 0`, and
  `discovery_truncated == 0`;
- `module_ambiguous == 0`, `session_cancel_ambiguities == 0`,
  `auth_state_ambiguities == 0`, and `fork_state_ambiguities == 0`;
- `in_flight_at_end == 0`, `pending_at_end == 0`, and the owned-run
  `child_still_running` field is present and false;
- `never`: `none/0/0/0`; and
- `auto`: `sigstop`, `pause_attempts = pause_confirmed >= 1`,
  `pause_partial = 0`.

There is no unavailable-loader predicate for Lane 16. Lane 02 deterministic
counts do not apply. `200000` defines the workload but is not an acceptance
count; `G3`, `136175`, function-call totals, timing, latency, median, and
performance values are non-authoritative.

## File structure and ownership

Commit this plan alone first so its commit is the implementation authority.
The later implementation commit modifies exactly:

- `scripts/verify-induced-gaps.sh` — Lane 07 receipt/finalizer/self-test;
- `scripts/matrix/verify-shared-layer.sh` — Lane 09 receipt and ID cleanup;
- `scripts/matrix/verify-fork-scope.sh` — Lane 10 receipt only;
- `scripts/matrix/verify-oracle.sh` — Lane 11 isolation/receipt and pinned Cargo;
- `scripts/build-release.sh` — sole Lane 14 receipt/finalizer;
- `scripts/verify-discover-containers.sh` — Lane 14-private nested facts;
- `scripts/verify-task4-lane16.sh` — Lane 16 workload/structural validator;
- `tests/artifact_contracts.rs` — table-driven lifecycle and lane mutations.

Do not add a shared receipt helper: the six scripts have different ephemeral
ownership and a generic API would increase the trust surface without removing
their lane-specific identity checks.

---

### Task 1: Commit the reviewed plan authority

**Files:**
- Create: `docs/superpowers/plans/2026-08-27-task4-receipt-closure.md`

**Produces:** One immutable implementation authority, separate from all code.

- [ ] **Step 1: Run plan self-review**

Compare every Lane 16 predicate with the production plan, confirm Lane 10's
current oracle remains unchanged, scan for prohibited placeholder language from
the writing-plans skill, and run `git diff --check`.

- [ ] **Step 2: Obtain independent approval**

Sol xhigh reviews architecture/security/lifecycle; Terra reviews executable
contracts and sequencing; Luna inventories literal paths/cardinalities. All
three must return PASS with no unresolved critical/important issue.

- [ ] **Step 3: Commit only the plan**

```sh
git add docs/superpowers/plans/2026-08-27-task4-receipt-closure.md
git commit -m "docs: plan remaining Task 4 receipts"
```

Do not add the unrelated OpenSSL report.

### Task 2: Add RED artifact and behavioral contracts

**Files:**
- Modify: `tests/artifact_contracts.rs`

**Consumes:** The exact normal/nested interfaces and root schema above.

**Produces:** One table-driven contract over all seven production drivers
(unchanged Lane 02 plus modified 07/09/10/11/14/16), plus lane-specific
cardinality/identity mutations.

- [ ] **Step 1: Add the table and prove RED**

For each modified normal driver, invoke `sh SCRIPT --self-test` and require its
success marker. Pin Lane 02's existing self-test unchanged. Run:

```sh
cargo +1.88 test --locked --test artifact_contracts task4_receipt -- --nocapture
```

Expected before implementation: FAIL because five scripts lack the interface
and Lane 16 does not exist.

- [ ] **Step 2: Encode lifecycle mutations**

Each lane-local self-test uses fake external commands and a temporary private
parent/root. It must cover complete success, input mutation before finalization,
body success plus cleanup/query failure, existing/non-private/symlink/foreign
root, missing ephemeral identity, and status-last ordering. Artifact contracts
must reject missing/early/duplicate status, changed HEAD/input ledger, foreign
terminal artifacts, missing capture/checker evidence, or a runtime/Cargo command
started during root-preflight rejection.

The behavioral table also holds `$CAMPAIGN/.task4.lock` from a separate fake
owner and proves every normal driver fails before body/Cargo/runtime execution;
after releasing that exact lock, the same driver's success fixture proceeds.

- [ ] **Step 3: Encode exact lane mutations**

Reject missing/duplicate G1–G5 or freeze artifacts; wrong Lane 09 broad/leaf
cardinality or IDs; wrong Lane 10 fork/four-row relationship; Lane 11 sibling
state or ledger mutation; Lane 14 missing/replaced nested facts; and either
Lane 16 structural-row mutation. Accept Lane 16 changes limited to
call/timing/performance values. Reject a Lane 16 bare/PATH observer,
unpinned/unlocked Cargo invocation, observer outside
`$ROOT/work/target/release`, or missing observer/Cargo identity ledger.

### Task 3: Implement lane-local receipts minimally

**Files:**
- Modify/Create: exactly the seven scripts listed under file ownership.

**Consumes:** Task 2 tests and existing lane oracles.

**Produces:** The exact interfaces, receipts, identity-bound cleanup, and
self-tests above with no product/checker/public-schema changes.

- [ ] **Step 1: Implement common-shaped code locally**

Use only POSIX shell, existing `scripts/lib.sh` functions, `flock`, `stat`,
`sha256sum`, `/proc`, and current Python/JQ code. Repeat the small validation
sequence inside each owner; do not create a helper file or new dependency.

- [ ] **Step 2: Preserve each body oracle**

Move work beneath the private root, wrap existing body execution, replace
mutable-name cleanup with recorded immutable identity cleanup, and retain
current assertions. For Lane 10 do not change `uncorroborated=1`. For Lane 11
pin Cargo and enforce state ownership. For Lane 14 pass only the private facts
path. Add the exact Lane 16 validator above.

- [ ] **Step 3: Run focused GREEN checks**

```sh
sh -n scripts/verify-induced-gaps.sh
sh -n scripts/matrix/verify-shared-layer.sh
sh -n scripts/matrix/verify-fork-scope.sh
sh -n scripts/matrix/verify-oracle.sh
sh -n scripts/build-release.sh
sh -n scripts/verify-discover-containers.sh
sh -n scripts/verify-task4-lane16.sh
sh scripts/verify-induced-gaps.sh --self-test
sh scripts/matrix/verify-shared-layer.sh --self-test
sh scripts/matrix/verify-fork-scope.sh --self-test
sh scripts/matrix/verify-oracle.sh --self-test
sh scripts/build-release.sh --self-test
sh scripts/verify-discover-containers.sh --self-test
sh scripts/verify-task4-lane16.sh --self-test
cargo +1.88 test --locked --test artifact_contracts task4_receipt -- --nocapture
```

No Docker, sudo, systemd, eBPF attachment, or production evidence is consumed
by these self-tests.

### Task 4: Verify and independently review the implementation

**Files:** The exact eight-file implementation diff only.

**Produces:** One reviewed gate-only commit.

- [ ] **Step 1: Run canonical verification serially**

```sh
cargo +1.88 fmt --all -- --check
cargo +1.88 check --locked --workspace --all-targets
cargo +1.88 test --locked --workspace --all-targets
cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
git diff --check
```

- [ ] **Step 2: Stop the writer and review**

Sol xhigh reviews cleanup authority, terminal reachability, source binding, and
oracle preservation. Terra reviews command/root/lock/runtime sequencing. Luna
checks file inventory, literal cardinalities, and no out-of-scope change. Fix
and repeat until all agree.

- [ ] **Step 3: Commit the exact gate-only delta**

```sh
git add scripts/verify-induced-gaps.sh \
  scripts/matrix/verify-shared-layer.sh \
  scripts/matrix/verify-fork-scope.sh \
  scripts/matrix/verify-oracle.sh scripts/build-release.sh \
  scripts/verify-discover-containers.sh \
  scripts/verify-task4-lane16.sh tests/artifact_contracts.rs
git commit -m "test: bind remaining Task 4 lane receipts"
```

### Task 5: Prove Lane 02 compatibility and run remaining Task 4 lanes

**Files:** Generated private evidence only; no Git changes unless fresh evidence
reproduces a separately reviewed oracle defect.

**Produces:** One serial, source-bound Task 4 board or a terminal stop at the
first `UNRUN`/`NON-PASS`.

- [ ] **Step 1: Freeze implementation tip and Lane 02 compatibility**

Create the compatibility report described above, revalidate the Lane 02 root,
and stop on overlap/mismatch. Do not rerun Lane 02 automatically.

- [ ] **Step 2: Run lanes once in exact order**

Use one new absent root for 07, 09, 10, 11, and 14, then one new absent root for
each Lane 16 mode. Hold the common campaign lock and stop immediately on status
77, nonzero status, missing status, body/oracle failure, input drift, cleanup
uncertainty, or privacy failure. Do not run any later lane after a stop.

- [ ] **Step 3: Independent evidence review and freeze**

Review exact roots, hashes, cardinalities, cleanup, privacy, and current-source
qualification. Amend only a fresh reproduced mismatch under separate review.
Only a clean reviewed board unlocks r3 and 9.2d; it does not itself claim
9.3, CI, Task 10, release, or whole-project completion.
