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

The tracked `mise.toml` selects stable Rust 1.98.1 and Kind 0.33.0 for the
later Kubernetes lane. The eBPF build also needs the exact nightly and linker
used by CI:

```sh
rustup toolchain install 1.98.1 --profile minimal --component rustfmt,clippy
rustup toolchain install nightly-2026-05-20 --profile minimal --component rust-src
mise install
mise exec -- cargo +1.98.1 install bpf-linker --version 0.10.4 --locked
```

The release Rust version is single-sourced from `.release-rust-version`
(currently 1.98.1): `mise.toml`, CI, and the shell/Python selectors all read
that file, so a future bump starts there. The release compiler is the only
supported toolchain; there is no older MSRV floor. When a new stable Rust
ships, adopt it: update `.release-rust-version`, `mise.toml`, and the crate
`rust-version` fields (the release compiler's major.minor).

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
access is host policy; the QEMU packages do not grant it. The existing Linux
5.15 guest/runtime qualification remains required even though the primary host
has changed.

## Pinned Git dependency

The only Git dependency is
[pkcs11-components](https://github.com/mingulov/pkcs11-components) (its
`pkcs11-module` and `pkcs11-types` crates and their `pkcs11-abi` dependency),
pinned to revision `d0a47c71d34294466bc41100ae6b5a5a329029d2` in every
manifest that names it and in both lockfiles (`Cargo.lock`, `crates/ebpf/Cargo.lock`). The repository is
public, so an ordinary networked fetch resolves it; no Git configuration or
local mirror is needed:

```sh
mise exec -- ./scripts/cargo.sh +1.98.1 fetch --locked
cargo +nightly-2026-05-20 fetch --locked --manifest-path crates/ebpf/Cargo.toml
```

`scripts/cargo.sh` first reconstructs the two patched crates from
`third-party/sources.json` (hash-pinned crates.io archives plus tracked
patches). A disconnected recipient uses a verified full offline source export
instead, which carries the complete Cargo dependency payload; see
[the offline build guide](build-offline.md).

## Canonical Rust gates

Run repository commands through `scripts/cargo.sh`; invoking Cargo directly
bypasses generated dependency preparation. Keep the existing toolchain
selectors and gate flags. Set a private disk-backed `TMPDIR` as described
in [contributor verification](../CONTRIBUTING.md#verification) before tests:

```sh
mise exec -- ./scripts/cargo.sh +1.98.1 fmt --all -- --check
mise exec -- ./scripts/cargo.sh +1.98.1 check --locked --workspace --all-targets
mise exec -- ./scripts/cargo.sh +1.98.1 test --locked --workspace --all-targets
mise exec -- ./scripts/cargo.sh +1.98.1 clippy --locked --workspace --all-targets -- -D warnings
```
