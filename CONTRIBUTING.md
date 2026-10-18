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

These sign-off instructions apply to external contributors. The repository
owner's own development commits do not require a sign-off.

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
implicitly. Use the release compiler (`.release-rust-version`) as the only supported
toolchain, bumped as new stable releases ship. Retain edition 2024 and Linux
x86-64 host support,
including the documented ia32 target compatibility.

Commit source, public documentation and reproducible test inputs. Generated
binaries, dependency trees, local evidence and internal planning/review
records do not belong in the source tree. Keep measurements tied to their
actual revision, kernel and workload; an ordinary test does not qualify a
privileged capture or a release artifact. Run privileged, container or VM
experiments only with the host owner's authorization.

## Verification

Choose checks by changed behavior and integration stage:

| Tier | Cadence | Checks |
| --- | --- | --- |
| V0 | Documentation/process only | Links, commands, public source/export boundaries and whitespace |
| V1 | Each fix/subtask | Regression at the real seam, healthy/failure controls and affected module/target tests; enumerate selectors and require actual execution |
| V2 | Coherent integration batch | fmt/check/clippy, affected library/integration suites and consumers of changed interfaces |
| V3 | Assembled candidate | Complete canonical host gates below, locally or in equivalent complete CI at that revision |
| V4 | Relevant installed behavior ready | Required native/BPF, ABI, privacy, platform, performance and installed/package acceptance |

Use V1 while iterating and self-review each subtask before committing. Use
independent review at integration milestones and the final candidate; review
residual fixes against their affected boundaries. A production edit alone does
not require V3 on every round. Broaden early for global wire/privacy contracts,
dependency/build changes or an unexplained failure, with the reason recorded.
Run affected named `artifact_contracts` tests during iteration and the complete
target at V3. Do not reduce final required test membership.

Remote CI can satisfy equivalent V3 checks without a second local full run.
Verify the tested SHA, flags and every required job/shard. A prior successful
run does not qualify changed behavior; rerun affected checks. Privileged/live
acceptance has its own environment and authorization requirements.

After integrating worker commits, check intervening changes to shared interfaces
and run the appropriate affected checks on the combined revision. Clean textual
application and separate worker passes do not establish combined correctness.
Ordinary CI covers default unignored tests; record required ignored, excluded,
feature and live cells separately with actual selectors and results. Do not use
membership counts or a blanket `--ignored` as evidence of positive coverage.

Register new or renamed Python suites in `scripts/run-python-suites.py` in the
same patch. Run `python3 -I scripts/run-python-suites.py --check` before a remote
push, and use that runner with affected standalone suite filenames to check
their execution. This catches missing registrations before expensive CI builds.

Run Rust checks through the repository wrapper so pinned dependency sources
are prepared consistently. For test temporary files, choose a private
writable directory on a disk filesystem with enough free space; a small
memory-backed `/tmp` can exhaust its quota during the native suites. Set
and export `TMPDIR` with that absolute path before running tests. Keep it short enough
for the operating system's Unix-domain socket path limit.

For example, enumerate and run an existing focused module before broadening:

```sh
mise exec -- ./scripts/cargo.sh +1.98.1 test --locked -p p11scope --lib key_operation_tests:: -- --list
mise exec -- ./scripts/cargo.sh +1.98.1 test --locked -p p11scope --lib key_operation_tests::
```

Check the output: libtest may exit successfully when a filter matches nothing.
The following is the complete V3 gate. Use `--no-fail-fast` on `test` when
collecting failures across targets; failed and timed-out targets remain failed.

```sh
mise exec -- ./scripts/cargo.sh +1.98.1 fmt --all -- --check
mise exec -- ./scripts/cargo.sh +1.98.1 check --locked --workspace --all-targets
mise exec -- ./scripts/cargo.sh +1.98.1 test --locked --workspace --all-targets
mise exec -- ./scripts/cargo.sh +1.98.1 clippy --locked --workspace --all-targets -- -D warnings
```

Keep incremental caches warm and serialize Cargo-heavy jobs on a shared host.
`CARGO_BUILD_JOBS` limits compilation, not test threads or subprocesses. Bound
fixture concurrency where necessary and diagnose load-sensitive failures in a
quiet lane; do not increase deadlines or rerun until green without a cause.
Separate CI runners can run the existing shards concurrently. Process-local
fixture locks do not protect shared paths across separate test binaries.

Record concise commands, source revision, counts, elapsed time and remaining
limitations with a change; no permanent log archive is required. Commit
messages use an area followed by an imperative summary, for example
`fix: preserve unavailable discovery evidence` or `docs: clarify capture
limits`. Release qualification follows [RELEASING.md](RELEASING.md).
