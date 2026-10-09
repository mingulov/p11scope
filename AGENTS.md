<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Working on p11scope

## Start here

Read [README.md](README.md) for product scope, [CONTRIBUTING.md](CONTRIBUTING.md)
for contribution terms and checks, and [docs/development.md](docs/development.md)
for build prerequisites. Operator behavior is documented in
[docs/usage.md](docs/usage.md); releases follow [RELEASING.md](RELEASING.md).
Use these public documents without assuming a maintainer's private workspace
or internal planning files exist.

## Development workflow

p11scope is in early development. Prioritize useful features, correctness,
clear output and efficient delivery. Run meaningful tests and normal code
reviews; keep source changes in commits and record concise results and open
issues. This does not require an evidence archive.

- Do not routinely create binary archives, source snapshots, hash manifests,
  custody records, duplicated logs or elaborate review packages. Keep temporary
  output only while it helps debugging or an active task.
- Tested binaries and completed build caches are disposable. References to them
  in old reports do not require preserving or archiving their bytes. Cleanup
  should protect source history, uncommitted work, active tasks and needed build
  inputs, without manufacturing new retention requirements.
- Report what was actually checked and its limitations. Do not turn requests to
  review, audit, verify or release a development version into requirements for
  compliance-style documentation or permanent artifact retention.
- Use heavier assurance or archival workflows only when explicitly requested
  for the task, or when those artifacts are themselves part of the feature under
  test. A hash used by the product is different from an archive of agent work.
- Revisit release assurance with the owner as the project approaches maturity
  (perhaps v0.9 or v1.0); do not impose it now or activate it solely by version.

## Code and build boundaries

- `src/` contains the observer CLI, discovery, attachment, event processing
  and profile generation. `crates/ebpf/` contains the kernel programs in a
  separate Cargo workspace; `crates/ebpf-common/` defines shared data.
- `crates/discover/` is the optional helper that executes provider code in
  its own process. Keep provider loading out of the observer process.
  `crates/manifest/` contains the shared manifest contract.
- Keep the release compiler (`.release-rust-version`) as the only supported
  toolchain, edition 2024, Linux x86-64 host support and the documented
  ia32 target compatibility. Do not assume the development host's libc,
  kernel, provider paths or system utilities are universal.
- Use `mise exec -- ./scripts/cargo.sh` for host Rust commands. The wrapper
  prepares hash-pinned patched dependencies; generated `third-party/src/`
  is not a place to make source changes. Dependency changes must account
  for both `Cargo.lock` and `crates/ebpf/Cargo.lock` and their manifests.
- Preserve the userspace, BPF and shared-code license boundaries and each
  file's SPDX identifier. Check [CONTRIBUTING.md](CONTRIBUTING.md) before
  moving code between them.

## Contracts and evidence

- Preserve [privacy allowlist v1](docs/privacy/allowlist-v1.md) and its
  [v2 extension](docs/privacy/allowlist-v2.md). Never broaden captured fields
  or introduce payload, key-material or PIN capture implicitly.
- Treat [profile schema v3](docs/schema/observed-profile-v3.md) and inherited
  [v2 semantics](docs/schema/observed-profile-v2.md) as public contracts.
  Coordinate producer, consumer, documentation and fixture changes.
- Keep discovery, attachment, observed calls and semantic attribution
  distinct. Missing observations remain unknown. Report refusals, loss,
  incomplete inventory and `PARTIAL` coverage honestly.
- Loading a module, locating a symbol or matching a manifest digest does
  not establish operator attestation or prove that an application called it.
  Preserve the documented manifest and physical-provider identity checks.
- Keep file-descriptor identity and `/proc/maps` identity in their own device
  domains: Btrfs `st_dev` can differ from the mapped device. Qualification
  scripts use `scripts/mapped-provider-pin.py` to hash and privately map the
  same held FD, following `src/discovery/identity.rs` and the manifest's
  `KernelSelfMappingProbe`. Never copy the expected device from the fixture
  or capture, drop device checks, or reopen a held object by its pathname.
- State which revision and kind of test produced a result when relevant.
  Unit tests, controlled provider workloads and real-application captures
  check different behavior; do not overstate their coverage. This is a reporting
  requirement, not a requirement to retain binaries or build caches.

## Verification

Run the checks relevant to the change. Code and dependency changes require
the canonical Rust gates below; BPF, privacy, discovery and packaging changes
also need their affected documented lanes. For documentation-only changes,
check links, commands, source-export boundaries and whitespace; do not claim
runtime qualification from those checks.

Before tests, export `TMPDIR` to a private writable directory on a disk
filesystem with enough space and a short path for Unix-domain sockets.
Follow host-specific workspace instructions when provided. Avoid a small
memory-backed `/tmp`. Existing native fixtures expect a conventional
`umask 022`; private evidence directories should still be created as 0700.

```sh
mise exec -- ./scripts/cargo.sh +1.98.1 fmt --all -- --check
mise exec -- ./scripts/cargo.sh +1.98.1 check --locked --workspace --all-targets
mise exec -- ./scripts/cargo.sh +1.98.1 test --locked --workspace --all-targets
mise exec -- ./scripts/cargo.sh +1.98.1 clippy --locked --workspace --all-targets -- -D warnings
```

When adding or changing CI, design for parallel jobs: split long checks
(test shards, coverage shards, lint, audit, scripts) into separate jobs that
run concurrently, within a reasonable job count (under the runner concurrency
limit, about 20). Every split must still prove it ran the full test set.

Privileged, container and VM experiments need the host owner's authorization.
Honor authorization already given for the task, check ownership of resources,
and clean up only resources created by the experiment. Do not disturb an
unrelated browser, service, VM, container or another agent's capture.

## Changes and Git history

- Inspect branch, worktree and status first. Preserve unrelated changes;
  use an isolated worktree when needed. Commit finished, verified work.
- Git worktree disk hygiene: always run `cargo clean` in a worktree before
  `git worktree remove` -- with cargo's build dir redirected outside the
  worktree (`build.build-dir`), removal orphans that worktree's cached build
  instead of deleting it. If removal refuses or the worktree stays idle, at
  least `cargo clean` it. Prefer `remove` over `rm -rf` (manual deletion needs
  a follow-up `git worktree prune`).
- Use the contributor's real configured Git identity; do not invent an
  automation identity or replace another contributor's attribution.
  The repository owner's development commits do not require sign-offs.
  The sign-off policy in [CONTRIBUTING.md](CONTRIBUTING.md) applies to external
  contributors; do not impose it on the owner or request approval over missing
  owner trailers.
- Keep development history flat. Integrate task changes with cherry-pick or
  fast-forward, not merge commits. Preserve task branches and their source commits.
- Follow `<area>: <imperative summary>` commit messages. History rewriting
  and pushing require explicit agreement. Never force-push as a routine
  way to resolve a diverged branch.
- Keep generated binaries, dependency trees, capture logs, credentials,
  internal plans, audit reports and agent state outside public source.
  Commit reproducible test inputs and public documentation.
- Stage release work on a branch, integrate the final commit into `main`,
  then follow the release runbook. Prefer a fast-forward when possible to
  preserve the tested commit. Re-run checks affected by later changes; do not
  report an old successful run as validation of changed behavior.
