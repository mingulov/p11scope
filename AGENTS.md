<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Working on p11scope

## Start here

Read [README.md](README.md) for product scope, [CONTRIBUTING.md](CONTRIBUTING.md)
for contribution terms and checks, and [docs/development.md](docs/development.md)
for build prerequisites. Operator behavior is documented in
[docs/usage.md](docs/usage.md); releases follow [RELEASING.md](RELEASING.md).
Use these public documents without assuming a maintainer's private workspace
or internal planning files exist.

## Code and build boundaries

- `src/` contains the observer CLI, discovery, attachment, event processing
  and profile generation. `crates/ebpf/` contains the kernel programs in a
  separate Cargo workspace; `crates/ebpf-common/` defines shared data.
- `crates/discover/` is the optional helper that executes provider code in
  its own process. Keep provider loading out of the observer process.
  `crates/manifest/` contains the shared manifest contract.
- Keep Rust 1.88, edition 2024, Linux x86-64 host support and the documented
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
- Keep measurements bound to the actual commit, binary, kernel and workload.
  Unit tests, controlled provider workloads and real-application captures
  establish different evidence; state which one was run.

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
mise exec -- ./scripts/cargo.sh +1.88 fmt --all -- --check
mise exec -- ./scripts/cargo.sh +1.88 check --locked --workspace --all-targets
mise exec -- ./scripts/cargo.sh +1.88 test --locked --workspace --all-targets
mise exec -- ./scripts/cargo.sh +1.88 clippy --locked --workspace --all-targets -- -D warnings
```

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
  Add the sign-off required by [CONTRIBUTING.md](CONTRIBUTING.md).
- Follow `<area>: <imperative summary>` commit messages. History rewriting
  and pushing require explicit agreement. Never force-push as a routine
  way to resolve a diverged branch.
- Keep generated binaries, dependency trees, capture logs, credentials,
  internal plans, audit reports and agent state outside public source.
  Commit reproducible test inputs and public documentation.
- Stage release work on a branch, integrate the final commit into `main`,
  then follow the release runbook. Prefer a fast-forward when possible to
  preserve the tested commit. A changed commit or tree needs explicitly
  reconciled evidence; never relabel an old receipt as a new successful run.
