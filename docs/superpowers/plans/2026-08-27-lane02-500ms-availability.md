# Lane 02 fixed 500 ms availability implementation plan

**Date:** 2026-08-27

**Status:** Proposed; execute only after the paired amendment and this plan pass
independent Sol, Terra, and Luna review and are committed together.

**Starting base:** `17c538ff6a73bf2aecd3ee539bee54732a964229`

**Goal:** Apply the fixed 500 ms owned-pause contract, prove it on both supported
kernel baselines, then rerun Lane 02 without changing its oracle.

## Commit and ownership model

1. Commit only this plan and
   `../specs/2026-08-27-slice1b2-500ms-pause-amendment.md` on the exact base.
   Call that reviewed docs-only commit `P`.
2. Create an isolated implementation worktree/branch at `P`.
3. One writer owns exactly:
   - `src/discovery/pause.rs`
   - `spike/slice1b2-kernel/src/main.rs`
   - `spike/slice1b2-kernel/run.sh`
4. Stop the writer before independent review. Do not amend commits.
5. Preserve the unrelated OpenSSL report and privacy allowlist unchanged.

## Task 1: Freeze RED contracts

In `src/discovery/pause.rs`, add or update focused tests proving:

- `cycle_deadline(10) == 500_000_010`;
- exactly the deadline is accepted and deadline + 1 is rejected;
- overflow fails closed;
- an existing earlier active/failure deadline is never extended;
- cleanup and successor paths reuse the same earliest fixed deadline;
- `auto` still becomes sticky partial after safe cleanup;
- `always` still refuses rather than completing unpaused.

Replace every absolute-100-ms fixture timestamp with an expression relative to
`CYCLE_NS` so it tests boundary behavior rather than the old policy value. The
exact base inventory is:

- `successor_requested_after_resume_deadline_is_protectively_resumed`;
- `resume_observation_witnesses_are_bounded_by_the_existing_deadline`;
- `all_stopped_at_the_resume_deadline_fails_without_waiting_past_it`;
- `deadline_checks_wrap_future_and_after_dequeue_fail_without_reset`;
- `changed_task_set_after_resume_is_a_valid_execution_witness`; and
- `rejected_helper_is_classified_before_all_timestamp_failures`.

In the isolated kernel spike, update tests/validator assertions first so the
unchanged 100 ms implementation fails for the expected ceiling mismatch. The
inventory includes `valid_signal`, rejected-request overflow/deadline tests,
mutation cases 43–46, the Rust and shell causal-deadline checks, the
`stop_wait_ceiling_us` field, and confirmation-sample ceiling checks.

Add a RED proving a confirmation after sample 101 but before 500 ms is valid.
Derive the maximum retained sample count as
`500_000 / 1_000 + 1 = 501` from the fixed ceiling and unchanged cadence in
both Rust and shell validation. The concrete sample-cap sites are
`spike/slice1b2-kernel/src/main.rs`'s `confirmation_samples_well_formed` and
`complete_accepted_cycle`, plus `run.sh`'s `samples_well_formed`. Exercise the
maximum serialized Gate B record and prove the existing 8 MiB per-file and
16 MiB total evidence caps still hold.

Capture the exact failing commands/output in
`.superpowers/sdd/2026-08-25-slice1b2-next-gates/progress.md` without rewriting
historical entries.

## Task 2: Minimum implementation

Change only:

```rust
const CYCLE_NS: u64 = 500_000_000;
```

and the isolated Gate A/B equivalents:

```rust
const STOP_WAIT_CEILING_US: u64 = 500_000;
```

Derive the Rust and shell maximum sample count from 500 ms / 1 ms plus one.
Update `spike/slice1b2-kernel/run.sh` checks for the confirmation ceiling,
causal deadline, `stop_wait_ceiling_us`, and maximum samples. Make mutation
timestamps and Rust fixtures relative to `STOP_WAIT_CEILING_NS`. Update factual
comments only. Do not change state transitions, cadence, deadline
anchor/clamping, Engine/attachment code, public output, BPF, schema, CLI, or
privacy.

The `spike/slice1b2-loader-host` binary/campaign is an excluded frozen
historical artifact: this plan neither builds nor runs it and derives no
product authority from it. Kernel unit tests may still read its unchanged
lifecycle shell as a contract fixture.

The exact implementation range `P..D` must contain only the three owned files.
Record `P`, implementation commit `D`, `D^{tree}`, and a SHA-256 of the binary
patch `git diff --binary P..D` before runtime.

## Task 3: Unprivileged verification and review

Run one Cargo-heavy command at a time:

```sh
cargo +1.88 fmt --all -- --check
cargo +1.88 check --locked --workspace --all-targets
cargo +1.88 test --locked --workspace --all-targets
cargo +1.88 clippy --locked --workspace --all-targets -- -D warnings
sh scripts/verify-task4-lane02.sh --self-test
python3 scripts/check-capture-evidence.py --self-test
sh scripts/verify-canaries.sh --self-test
git diff --check
```

Run the isolated spike checks explicitly:

```sh
cargo +1.88 test --locked --manifest-path spike/slice1b2-kernel/Cargo.toml
cargo +1.88 clippy --locked --manifest-path spike/slice1b2-kernel/Cargo.toml --all-targets -- -D warnings
bash -n spike/slice1b2-kernel/run.sh
python3 spike/slice1b2-kernel/check-init-shape.py --pause-fingerprint-self-test
spike/slice1b2-kernel/run.sh build-fixture ABSENT_PRIVATE_FIXTURE_OUTPUT
```

`build-fixture` invokes the C fixture self-check only. Do not execute the
Jammy-built Rust runner on the Linux-7.0 controller host: its identity oracle
correctly accepts only the retained Jammy/Noble guests. Preserve the existing
provisioned Rust tests and guest self-check/lane behavior, with exact command
output and exit status in the ledger.

Fresh Sol xhigh, Terra, and Luna review must agree that:

- the diff is a fixed policy value only;
- every absolute fixture became constant-relative without weakening a case;
- no deadline reset/adaptation or safety/privacy/ABI/public change exists;
- campaign inputs and validators bind 500 ms exactly;
- no Critical or Important issue remains.

Commit the reviewed implementation as a new commit `D`.

## Task 4: Freeze runtime inputs

Create a new absent mode-0700 Gate A/B campaign root. Never reuse prior Slice
1b-2 or Lane 02 roots. Use only the public
`spike/slice1b2-kernel/run.sh` interfaces; do not claim the separate product
preflight harness exists. Before execution, bind these exact commands and
arguments in a read-only command ledger:

```sh
RUN=spike/slice1b2-kernel/run.sh
export P11SCOPE_SPIKE_ACCEL=kvm
"$RUN" build-bpf "$ROOT/source"
SOURCE_ARCHIVE="$ROOT/source/source.tar"
SOURCE_MANIFEST="$ROOT/source/source-elf.manifest"
SOURCE_MANIFEST_SHA256="$(sha256sum "$SOURCE_MANIFEST" | awk '{print $1}')"
"$RUN" provision-jammy "$SOURCE_ARCHIVE" "$SOURCE_MANIFEST" \
  "$SOURCE_MANIFEST_SHA256" "$ROOT/provision-jammy" "$ROOT/build"
"$RUN" freeze-execution "$ROOT/source" "$ROOT/build" "$ROOT/bundle"
"$RUN" gate-a-lane jammy "$ROOT/bundle" "$ROOT/gate-a-jammy-run" \
  "$ROOT/gate-a-jammy-export"
"$RUN" gate-a-lane noble "$ROOT/bundle" "$ROOT/gate-a-noble-run" \
  "$ROOT/gate-a-noble-export"
"$RUN" gate-b-lane jammy "$ROOT/bundle" "$ROOT/gate-b-jammy-N-run" \
  "$ROOT/gate-b-jammy-N-export"
"$RUN" gate-b-lane noble "$ROOT/bundle" "$ROOT/gate-b-noble-N-run" \
  "$ROOT/gate-b-noble-N-export"
```

For Gate B, `N` is exactly 1, 2, then 3 for each kernel. Each command gets a
new absent run/export directory. The parent controller executes this fixed
sequence serially, records exit status and cleanup, and has no retry branch.
It requires writable `/dev/kvm`, records
`P11SCOPE_SPIKE_ACCEL=kvm`, and rejects any lane whose retained accelerator is
not KVM.

The freeze binds:

- exact `P`, `D`, tree, source patch hash, binaries, BPF object/inventory,
  runner, validator, fixture, compiler/toolchain, caps, and oracle;
- Jammy image SHA-256
  `6de0c42a98dc9a749917dfef34bf54e3595441bf67d39f103a61341560b3da8e`;
- Noble image SHA-256
  `6e40c07ae715f744f84af0bec76415cc1987dd115b4b8de437818561f01a3733`;
- exact QEMU/KVM, kernel/userland, provider, loader/libc, and cleanup identities;
- zero initial attempts.

The controller validates every frozen input and zero prior lane exports before
the first boot. A changed or missing input stops as `UNRUN/review`; it is never
replaced after execution. The public six-file execution bundle remains
unchanged. A separate reviewed campaign-provenance ledger records `P`, `D`,
`D^{tree}`, the implementation-patch digest, command ledger, image/QEMU/KVM
identities, and bundle manifest digest; it is hashed, made read-only, and
verified before the first lane. Reviews require both artifacts and never claim
the external ledger is part of the execution manifest.

The owner's standing 2026-08-25 authorization explicitly covers task-related
root, KVM/VM, container, A/B, and diagnostic experiments. The controller
records that authority before the first privileged command; absent or narrower
authority stops as `UNRUN`.

## Task 5: Kernel Gate A/B campaign

Use the existing corrected no-busy-wait campaign and unchanged semantic oracle:

1. Gate A once on Jammy 5.15.
2. Gate A once on Noble 6.8.
3. Gate B three cold boots × 20 fresh children on Jammy.
4. Gate B three cold boots × 20 fresh children on Noble.

Run all predeclared safe lanes even after an ordinary semantic failure. Stop
after safe cleanup for host-safety, provenance, resume, detach, reap, cleanup
drain/map failure, quiescence, residue, or privacy failure. Do not replace,
repeat, append, or edit an attempt, input, runner, validator, or oracle.

Acceptance is both Gate A passes and Gate B 120/120. Every child must retain
one exact winner/coalesced classification, stopped-set samples, required
attachments, empty drain, original-pidfd resume, markers, counters, teardown,
and hook-relative 500 ms checks. Report observed stop/resume tails as bounded
campaign facts, never as an arbitrary-scheduler guarantee.

## Task 6: Host Lane 02 candidate-selection gate

On the measured host, run one new absent six-row root with the reviewed product
candidate and existing driver. It executes exactly:

```text
(initial-set|dlopen) × (never|auto|always)
```

Require 6/6 using the unchanged Lane 02 checker and oracle: 68 slots, 136/136
probes, exact fixture counts plus one bootstrap
`C_GetFunctionList`, one authorized owned timing-proof projection, no loader
unavailable strategy, `never=none/0/0/0`, and pause-enabled rows
`sigstop` with `attempts=confirmed>=1` and `partial=0`.

Every row requires complete cleanup/quiescence and a final exact-process
absence receipt. A safe `always` refusal remains containment-correct but makes
the row and candidate non-pass.

This isolated root is candidate-selection evidence only. It does not discharge
the active production Task 4 Lane 02 row, the remaining serial Task 4 round,
or any r3/9.2d condition. After a passing amendment decision, Task 4 restarts
from its required fresh Lane 02 invocation and exact current candidate. The
later 9.3 campaign remains the product's two-kernel integration authority.

## Task 7: Independent evidence decision

One fresh Sol xhigh reviewer recomputes all raw evidence. Terra independently
checks campaign cardinality and lifecycle/cleanup. Luna checks identities,
hashes, oracle fields, and privacy-negative scans. The controller reconciles
all findings.

The candidate passes only if every predeclared Gate A/B and Lane 02 predicate
passes. Any timeout, partial/refusal, identity drift, missing receipt, privacy
failure, cleanup uncertainty, or residue is `NON-PASS`. Do not increase the
bound or rerun.

If the candidate passes, commit the factual amendment disposition and update
the active production/next-gates/ROADMAP references from 100 ms to 500 ms.
Then rerun the complete remaining Task 4 sequence beginning with fresh Lane 02;
only that reviewed gate round can unlock r3/9.2d. The later 9.3 Jammy/Noble
product campaign remains mandatory before release. Public README/usage status
still waits for Task 10 and exact-tip CI.

## Rejected work

- the untracked four-file phase/affinity diagnostic draft; independent review
  found outcome pooling, missing receipt ownership, privacy widening, and
  disproportionate scope;
- any configurable/adaptive value, timeout retry, anchor movement, stage reset,
  product affinity, real-time scheduling, or `never`-only scope;
- `uprobe_multi` or another attachment backend for the Linux-5.15 gate;
- reuse or amendment of historical evidence.
