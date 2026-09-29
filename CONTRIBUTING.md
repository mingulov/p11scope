<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Contributing to p11scope

## License

```text
Public license: GPL-3.0-or-later
BPF sources: GPL-2.0-only
Shared BPF/userspace definitions (crates/ebpf-common): GPL-2.0-or-later
```

Userspace code, docs, and scripts are licensed under GPL-3.0-or-later
(see `LICENSE`); BPF programs are licensed under GPL-2.0-only
(see `LICENSES/GPL-2.0-only.txt`). `crates/ebpf-common` is compiled into both
the BPF object and the observer, so it is licensed under GPL-2.0-or-later
(see `LICENSES/GPL-2.0-or-later.txt`), which each side can use under its own
terms. Per-file SPDX tags state which applies to each file.

## Contributions

```text
Contributions: CLA granting broad sublicensing/relicensing rights
```

By contributing, you agree that your contribution is made under the license
of the files you touch (above), and that you grant the project broad rights
to sublicense and relicense your contribution, including under future or
additional licenses. This grant is what allows the project to relicense
freely later; a sign-off alone does not grant it.

## How to sign

Add a `Signed-off-by:` trailer to each commit (`git commit -s`):

```text
Signed-off-by: Your Name <you@example.com>
```

The sign-off certifies that you wrote the contribution or otherwise have the
right to submit it under the terms above, and that you agree to the
contribution terms in this file.

## Product and source boundaries

Start with [README.md](README.md), the [operator guide](docs/usage.md), and
[development setup](docs/development.md). [AGENTS.md](AGENTS.md) summarizes
repository navigation and working rules for coding agents. The versioned
[profile schema](docs/schema/observed-profile-v3.md) and
[privacy allowlist](docs/privacy/allowlist-v1.md), including its
[v2 extension](docs/privacy/allowlist-v2.md), define the public contracts.
Keep changes scoped, preserve unrelated work, and never broaden capture
implicitly. Retain Rust 1.88, edition 2024, and Linux x86-64 host support,
including the documented ia32 target compatibility.

Commit source, public documentation and reproducible test inputs. Generated
binaries, dependency trees, local evidence and internal planning/review
records do not belong in the source tree. Keep measurements tied to their
actual revision, kernel and workload; an ordinary test does not qualify a
privileged capture or a release artifact. Run privileged, container or VM
experiments only with the host owner's authorization.

## Verification

Run Rust checks through the repository wrapper so pinned dependency sources
are prepared consistently. For test temporary files, choose a private
writable directory on a disk filesystem with enough free space; a small
memory-backed `/tmp` can exhaust its quota during the native suites. Set
and export `TMPDIR` with that absolute path before running tests. Keep it short enough
for the operating system's Unix-domain socket path limit.

```sh
mise exec -- ./scripts/cargo.sh +1.88 fmt --all -- --check
mise exec -- ./scripts/cargo.sh +1.88 check --locked --workspace --all-targets
mise exec -- ./scripts/cargo.sh +1.88 test --locked --workspace --all-targets
mise exec -- ./scripts/cargo.sh +1.88 clippy --locked --workspace --all-targets -- -D warnings
```

Record the commands, source revision and results with a change. Commit
messages use an area followed by an imperative summary, for example
`fix: preserve unavailable discovery evidence` or `docs: clarify capture
limits`. Release qualification follows [RELEASING.md](RELEASING.md).
