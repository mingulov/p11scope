<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Development setup

Ubuntu 26.04 is the primary development host. It does not narrow the product
contract: p11scope remains portable across the older and different Linux
distributions, kernels, libc implementations, GNU coreutils/uutils
environments, and supported Rust toolchains described by the
[operator guide](usage.md) and [release qualification record](../CHANGELOG.md#qualification-of-this-release).
Do not add Ubuntu-specific runtime behavior or use host binary layouts as fixtures.

## Ubuntu 26.04 host

Install the host build prerequisites from the Ubuntu repositories:

```sh
sudo apt-get update
sudo apt-get install -y ca-certificates curl git build-essential gcc-multilib \
  clang-18 llvm jq libseccomp-dev pkg-config python3 bpftool bpftrace
```

Install mise and rustup as your normal user. Keep their standard per-user
locations: mise data under `~/.local/share/mise`, rustup toolchains under
`~/.rustup`, and Cargo state and installed tools under `~/.cargo`. Do not set
project-specific `MISE_DATA_DIR`, `RUSTUP_HOME`, or `CARGO_HOME` values.

The tracked `mise.toml` selects stable Rust 1.99.1 and Kind 0.33.0 for the
later Kubernetes lane. The eBPF build also needs the exact nightly and linker
used by CI:

```sh
rustup toolchain install 1.99.1 --profile minimal --component rustfmt,clippy
rustup toolchain install nightly-2026-05-20 --profile minimal --component rust-src
mise install
mise exec -- cargo +1.99.1 install bpf-linker --version 0.10.4 --locked
```

The release Rust version is defined by `.release-rust-version` (currently
1.99.1). CI and shell/Python selectors read that file; `mise.toml` and host
manifest floors are kept in sync with it, so a future bump starts there. The
release compiler is the only supported toolchain; there is no older MSRV
floor. When a new stable Rust
ships, adopt it: update `.release-rust-version`, `mise.toml`, and the crate
`rust-version` fields (the release compiler's major.minor).

The BPF comparison job additionally installs Rust 1.98.1 to rebuild its
immutable historical baseline. Its candidate uses 1.99.1; the comparison
records both exact compiler commits and keeps the shared BPF tools fixed.

Keep `~/.cargo/bin` on `PATH` so Cargo-installed tools such as `bpf-linker`
are directly discoverable. The later container lanes also require a working
Docker daemon; verify both client and server access before running them:

```sh
command -v bpf-linker
bpf-linker --version | grep -Fx 'bpf-linker 0.10.4'
mise exec -- kind version
docker version
```

Privileged runtime qualification additionally requires `sudo -n`, `bpftool`,
`bpftrace`, and `systemd-run`. These are runtime-lane prerequisites rather than
requirements for ordinary unprivileged builds. Run privileged lanes only when
they are explicitly authorized.

SoftHSM is optional for the local provider lanes:

```sh
sudo apt-get install -y softhsm2
```

QEMU/KVM qualification is also optional. The active Ubuntu 26.04 host lane is
pinned to both QEMU and qemu-img 10.2.1; install the distro packages and verify
both versions before using that lane:

```sh
sudo apt-get install -y qemu-system-x86 qemu-utils
qemu-system-x86_64 --version | sed -n '1p' | grep -E '^QEMU emulator version 10\.2\.1([ (]|$)'
qemu-img --version | sed -n '1p' | grep -E '^qemu-img version 10\.2\.1([ (]|$)'
test -r /dev/kvm && test -w /dev/kvm
```

The active lane refuses another or mixed QEMU/qemu-img version. KVM device
access is host policy; the QEMU packages do not grant it. Current positive guest qualification uses Multi-capable hosts, normally 6.6+
and working backports. One combined stock pre-Multi refusal guest verifies
`uprobe-multi-required`, unchanged sinks, an unstarted workload and offline
command availability; it supplies no positive load or headroom evidence.
Historical 5.15/6.1 results retain their original outcomes.

## Manual Docker runtime workflow

[Docker runtime](../.github/workflows/docker-runtime.yml) runs the existing
minimum container capture directly on an `ubuntu-26.04` hosted VM, using its
local Docker daemon. Supply `preview_run_id` for this exact source SHA from
either a successful same-repository CI release-preview or a completed
[package-preview](../.github/workflows/package-preview.yml) run. The latter
requires successful `validate` and `package-full` jobs with their real gate
steps in the selected attempt; an independently failed or absent P0 job does
not invalidate FULL. Package-preview's validation already binds successful
ordinary and coverage CI to that source. The consumer never guesses another
covering CI run, and the CI release-preview route still requires overall success.

The consumer verifies the recognized workflow identity, source/tree, attempt,
FULL public package, compiler pins, checksums and static x86-64 observer. It
requires artifact creation within the selected FULL producer job's execution
interval, excluding artifacts left by earlier attempts of the same run. It
rechecks the run's source, attempt and terminal state after package validation,
before creating executable output. Absent, expired, mismatched or P0 artifacts
fail. It neither starts a preview nor builds a replacement observer. This
public package consumer does not provide default/WIDE libtest fanout artifacts.

The job holds one owned privileged lane, uses private disk work directories,
and checks actual Docker/cgroup/storage, BTF, resources, functional Multi,
return-probe safety and embedded FULL capture before the unchanged
`scripts/matrix/verify-docker.sh` body runs. Its original nine-function,
226-call workload, bootstrap call, count multiset, clean metrics, provider
identity and unprivileged diagnostics remain required. Missing records,
UNRUN/nonzero status, loss and resource cleanup failures fail the job. The
25-minute outer timeout is an initial scheduling budget, not a measurement.

Source and stub checks do not establish runtime qualification. The ordinary
scripts job still reports this live body UNRUN in that job; only an actual
successful manual Docker runtime run supplies this minimum positive. D1
shared-layer/copy-up, Kubernetes, Knative and performance qualification remain
separate. The manual job retains its diagnostics for seven days, checks owned
container/image/process and BPF link/program/map cleanup, and never prunes the daemon.

## Pinned Git dependency

The only Git dependency is
[pkcs11-components](https://github.com/mingulov/pkcs11-components) (its
`pkcs11-module` and `pkcs11-types` crates and their `pkcs11-abi` dependency),
pinned to revision `d0a47c71d34294466bc41100ae6b5a5a329029d2` in every
manifest that names it and in both lockfiles (`Cargo.lock`, `crates/ebpf/Cargo.lock`). The repository is
public, so an ordinary networked fetch resolves it; no Git configuration or
local mirror is needed:

```sh
mise exec -- ./scripts/cargo.sh +1.99.1 fetch --locked
cargo +nightly-2026-05-20 fetch --locked --manifest-path crates/ebpf/Cargo.toml
```

`scripts/cargo.sh` first reconstructs the two patched crates from
`third-party/sources.json` (hash-pinned crates.io archives plus tracked
patches). A disconnected recipient uses a verified full offline source export
instead, which carries the complete Cargo dependency payload; see
[the offline build guide](build-offline.md).

## Canonical Rust gates

Use the [verification tiers](../CONTRIBUTING.md#verification) while developing:
focused tests for each subtask, affected checks for an integration batch, then
these complete gates on the assembled candidate. A complete equivalent CI run
at that revision can supply the host gate; do not automatically repeat it
locally. BPF/live/package acceptance still needs its own applicable checks.

Run repository commands through `scripts/cargo.sh`; invoking Cargo directly
bypasses generated dependency preparation. Keep the existing toolchain
selectors and gate flags. Set a private disk-backed `TMPDIR` as described
in [contributor verification](../CONTRIBUTING.md#verification) before tests:

```sh
mise exec -- ./scripts/cargo.sh +1.99.1 fmt --all -- --check
mise exec -- ./scripts/cargo.sh +1.99.1 check --locked --workspace --all-targets
mise exec -- ./scripts/cargo.sh +1.99.1 test --locked --workspace --all-targets
mise exec -- ./scripts/cargo.sh +1.99.1 clippy --locked --workspace --all-targets -- -D warnings
```
