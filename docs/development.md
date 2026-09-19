<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Development setup

Ubuntu 26.04 is the primary development host. It does not narrow the product
contract: p11scope remains portable across the older and different Linux
distributions, kernels, libc implementations, GNU coreutils/uutils
environments, and supported Rust toolchains covered by the release plans. Do
not add Ubuntu-specific runtime behavior or use host binary layouts as fixtures.

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

The tracked `mise.toml` selects stable Rust 1.88.0 and Kind 0.33.0 for the
later Kubernetes lane. The eBPF build also needs the exact nightly and linker
used by CI:

```sh
rustup toolchain install 1.88.0 --profile minimal --component rustfmt,clippy
rustup toolchain install nightly-2026-05-20 --profile minimal --component rust-src
mise install
mise exec -- cargo +1.88 install bpf-linker --version 0.10.4 --locked
```

Keep `~/.cargo/bin` on `PATH` so Cargo-installed tools such as `bpf-linker`
are directly discoverable. The later container lanes also require a working
Docker daemon; verify both client and server access before running them:

```sh
command -v bpf-linker
bpf-linker --version | grep -Fx 'bpf-linker 0.10.4'
mise exec -- kind version
docker version
```

Privileged W7 qualification additionally requires `sudo -n`, `bpftool`,
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

## Pinned Git dependency bootstrap

The lockfile requires `pkcs11-proxy-ng` commit
`cbf3d019c43cf424d92a5d2033c6714c9f866f65`. A normal public fetch of that
revision is not known to work on this machine. The transferred sibling checkout
at `/home/user/src/m/pkcs11-proxy-ng-ws/pkcs11-proxy-ng` contains the commit.
Verify it and direct this one fetch to the transferred object database:

```sh
proxy_checkout=/home/user/src/m/pkcs11-proxy-ng-ws/pkcs11-proxy-ng
proxy_revision=cbf3d019c43cf424d92a5d2033c6714c9f866f65
test "$(git -C "$proxy_checkout" rev-parse --verify "$proxy_revision^{commit}")" = \
  "$proxy_revision"
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0="url.file://$proxy_checkout.insteadOf" \
GIT_CONFIG_VALUE_0=https://github.com/mingulov/pkcs11-proxy-ng \
CARGO_NET_GIT_FETCH_WITH_CLI=true \
  mise exec -- ./scripts/cargo.sh +1.88 fetch --locked
```

This leaves global and repository Git configuration unchanged. Set
`proxy_checkout` to the transferred checkout's canonical absolute path on a
different machine. The alternative for a disconnected recipient is a verified
full offline source export, which includes the complete Cargo dependency
payload; follow [the offline build guide](build-offline.md) instead of trying a
public fetch.

## Canonical Rust gates

Run repository commands through `scripts/cargo.sh`; invoking Cargo directly
bypasses generated dependency preparation. Keep the existing toolchain
selectors and gate flags:

```sh
mise exec -- ./scripts/cargo.sh +1.88 fmt --all -- --check
mise exec -- ./scripts/cargo.sh +1.88 check --locked --workspace --all-targets
mise exec -- ./scripts/cargo.sh +1.88 test --locked --workspace --all-targets
mise exec -- ./scripts/cargo.sh +1.88 clippy --locked --workspace --all-targets -- -D warnings
```
